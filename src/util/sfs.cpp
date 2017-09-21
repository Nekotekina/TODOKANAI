#include "sfs.hpp"
#include <algorithm>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef _WIN32
#define NOMINMAX
#include <Windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#ifdef _WIN32
std::unique_ptr<wchar_t[]> sfs::wpath(const std::string& utf8_path)
{
	// String size + null terminator
	const std::size_t buf_size = utf8_path.size() + 1;
	const int size = static_cast<int>(buf_size);

	// Buffer for max possible output length
	std::unique_ptr<wchar_t[]> buffer(new wchar_t[buf_size]);
	MultiByteToWideChar(CP_UTF8, 0, utf8_path.c_str(), size, buffer.get(), size);
	return buffer;
}

static std::string utf8_path(const wchar_t* wstr)
{
	// String size
	const std::size_t length = std::wcslen(wstr);
	const int buf_size = static_cast<int>(length * 3 + 1);

	std::string result;
	result.resize(buf_size - 1);
	result.resize(WideCharToMultiByte(CP_UTF8, 0, wstr, static_cast<int>(length) + 1, &result.front(), buf_size, NULL, NULL) - 1);
	return result;
}
#endif

std::unique_ptr<sfs::view> sfs::make_view(const std::string& path, const uchar* aes256_key)
{
#ifdef _WIN32
	auto handle = CreateFileW(wpath(path).get(), GENERIC_READ | GENERIC_WRITE | DELETE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	if (handle == INVALID_HANDLE_VALUE)
	{
		return nullptr;
	}
#else
	int handle = ::open(path.c_str(), O_RDWR | O_CREATE, S_IRUSR | S_IWUSR);

	if (handle == -1)
	{
		return nullptr;
	}

#endif

	return std::make_unique<sfs::view>(std::move(handle), aes256_key);
}

std::vector<std::string> sfs::find_all(const std::string& path, bool directories)
{
#ifdef _WIN32
	WIN32_FIND_DATAW found;
	const auto handle = FindFirstFileExW(wpath(path + "/*").get(), FindExInfoBasic, &found, FindExSearchNameMatch, NULL, FIND_FIRST_EX_CASE_SENSITIVE | FIND_FIRST_EX_LARGE_FETCH);

	if (handle == INVALID_HANDLE_VALUE)
	{
		return {};
	}

	std::vector<std::string> result;

	do
	{
		if (((found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == directories)
		{
			if (directories && found.cFileName[0] == '.')
			{
				if ((found.cFileName[1] == '.' && found.cFileName[2] == '\0') || found.cFileName[1] == '\0')
				{
					continue;
				}
			}

			result.emplace_back(utf8_path(found.cFileName));
		}
	}
	while (FindNextFileW(handle, &found));

	if (GetLastError() != ERROR_NO_MORE_FILES)
	{
		result.clear();
	}

	FindClose(handle);
	return result;
#else
	::DIR* const ptr = ::opendir(path.c_str());

	if (!ptr)
	{
		return {};
	}

	std::vector<std::string> result;

	while (const auto found = ::readdir(ptr))
	{
		if ((found->d_type == DT_DIR) == directories)
		{
			if (directories && found->d_name[0] == '.')
			{
				if (found->d_name[1] == '.' && found->d_name[2] == '\0' || found->d_name[1] == '\0')
				{
					continue;
				}
			}

			result.emplace_back(found->d_name);
		}
	}

	::closedir(ptr);
	return result;
#endif
}

sfs::view::view(handle&& _handle, const uchar* aes256_key)
	: m_handle(_handle)
{
	m_enc = EVP_CIPHER_CTX_new();
	m_dec = EVP_CIPHER_CTX_new();

	if (m_enc && (EVP_EncryptInit_ex(m_enc, EVP_aes_256_gcm(), nullptr, aes256_key, nullptr) != 1 ||
		EVP_CIPHER_CTX_ctrl(m_enc, EVP_CTRL_GCM_SET_IVLEN, 16, nullptr) != 1))
	{
		EVP_CIPHER_CTX_free(m_enc);
		m_enc = nullptr;
	}

	if (m_dec && (EVP_DecryptInit_ex(m_dec, EVP_aes_256_gcm(), nullptr, aes256_key, nullptr) != 1 ||
		EVP_CIPHER_CTX_ctrl(m_dec, EVP_CTRL_GCM_SET_IVLEN, 16, nullptr) != 1))
	{
		EVP_CIPHER_CTX_free(m_dec);
		m_dec = nullptr;
	}

#ifdef _WIN32
	LARGE_INTEGER size;
	GetFileSizeEx(m_handle, &size);
	m_count = size.QuadPart / 4096;
#else
	struct ::stat info;
	::fstat(m_handle, &info);
	m_count = info.st_size / 4096;
#endif

	std::memset(m_buf, 0, sizeof(m_buf));

#ifdef _WIN32
	_handle = INVALID_HANDLE_VALUE;
#else
	_handle = -1;
#endif
}

sfs::view::~view()
{
	OPENSSL_cleanse(m_buf, sizeof(m_buf));

	if (m_enc)
	{
		EVP_CIPHER_CTX_free(m_enc);
	}

	if (m_dec)
	{
		EVP_CIPHER_CTX_free(m_dec);
	}

	// Automatically delete empty storages
	if (m_count || !set_delete())
	{
#ifdef _WIN32
		FILE_END_OF_FILE_INFO _eof;
		_eof.EndOfFile.QuadPart = m_count * 4096;
		SetFileInformationByHandle(m_handle, FileEndOfFileInfo, &_eof, sizeof(_eof));
#else
		::ftruncate(m_handle, m_count * 4096);
#endif

		// TODO: screw the date/time
	}

#ifdef _WIN32
	CloseHandle(m_handle);
#else
	::close(m_handle);
#endif
}

bool sfs::view::read_block(std::uint64_t block, uchar* buf, std::uint64_t ident)
{
	// File buffer
	alignas(16) uchar fblock[4096];

	if (!m_dec || block >= m_count)
	{
		return false;
	}

#ifdef _WIN32
	LARGE_INTEGER fptr;
	fptr.QuadPart = block * 4096;
	if (!SetFilePointerEx(m_handle, fptr, nullptr, FILE_BEGIN))
	{
		return false;
	}

	DWORD rlen;
	if (!ReadFile(m_handle, fblock, sizeof(fblock), &rlen, nullptr) || rlen != sizeof(fblock))
	{
		return false;
	}
#else
	if (::lseek(m_handle, block * 4096, SEEK_SET) == -1 || ::read(m_handle, fblock, sizeof(fblock)) == -1)
	{
		return false;
	}
#endif

	// Block-specific additional authenticated data
	block_aad aad;
	aad.ident = ident;
	aad.index = block;

	// Decrypt block and verify auth tag
	int len;

	if (EVP_DecryptInit_ex(m_dec, nullptr, nullptr, nullptr, fblock) != 1 ||
		EVP_DecryptUpdate(m_dec, nullptr, &len, reinterpret_cast<uchar*>(&aad), sizeof(aad)) != 1 ||
		EVP_DecryptUpdate(m_dec, buf, &len, fblock + 16, sfs::block_size) != 1 ||
		EVP_CIPHER_CTX_ctrl(m_dec, EVP_CTRL_GCM_SET_TAG, 16, fblock + 4080) != 1 ||
		EVP_DecryptFinal_ex(m_dec, buf + len, &len) <= 0)
	{
		return false;
	}

	return true;
}

bool sfs::view::write_block(std::uint64_t block, const uchar* buf, std::uint64_t ident)
{
	// File buffer
	alignas(16) uchar fblock[4096];

	// Check state and generate random nonce
	if (!m_enc || block > m_count || RAND_bytes(fblock, 16) != 1)
	{
		return false;
	}

	// Block-specific additional authenticated data
	block_aad aad;
	aad.ident = ident;
	aad.index = block;

	// Encrypt block and write auth tag
	int len;

	if (EVP_EncryptInit_ex(m_enc, nullptr, nullptr, nullptr, fblock) != 1 ||
		EVP_EncryptUpdate(m_enc, nullptr, &len, reinterpret_cast<uchar*>(&aad), sizeof(aad)) != 1 ||
		EVP_EncryptUpdate(m_enc, fblock + 16, &len, buf, sfs::block_size) != 1 ||
		EVP_EncryptFinal_ex(m_enc, fblock + 16 + len, &len) != 1 ||
		EVP_CIPHER_CTX_ctrl(m_enc, EVP_CTRL_GCM_GET_TAG, 16, fblock + 4080) != 1)
	{
		return false;
	}

	// Write data
#ifdef _WIN32
	LARGE_INTEGER fptr;
	fptr.QuadPart = block * 4096;
	if (!SetFilePointerEx(m_handle, fptr, nullptr, FILE_BEGIN))
	{
		return false;
	}

	DWORD wlen;
	if (!WriteFile(m_handle, fblock, sizeof(fblock), &wlen, nullptr) || wlen != sizeof(fblock))
	{
		return false;
	}
#else
	if (::lseek(m_handle, block * 4096, SEEK_SET) == -1 || ::write(m_handle, fblock, sizeof(fblock)) == -1)
	{
		return false;
	}
#endif

	// Update file size if appending
	if (block == m_count)
	{
		m_count = block + 1;
	}

	return true;
}

void sfs::view::flush()
{
#ifdef _WIN32
	FlushFileBuffers(m_handle);
#else
	::fsync(m_handle);
#endif
}

bool sfs::view::alloc(std::uint64_t future_size)
{
	// Convert to real filesizes
	const std::uint64_t old_rs = m_count * 4096;
	const std::uint64_t new_rs = future_size / block_size * 4096 + (future_size % block_size ? 4096 : 0);

	if (old_rs >= new_rs)
	{
		return true;
	}

	// Limit absurd values
	if (future_size > 1024ull * 1024 * 1024 * 1024 * 1024 /* 1024 TiB */)
	{
		return false;
	}

#ifdef _WIN32
	FILE_ALLOCATION_INFO _all;
	_all.AllocationSize.QuadPart = new_rs;
	if (!SetFileInformationByHandle(m_handle, FileAllocationInfo, &_all, sizeof(_all)))
	{
		return false;
	}
#elif __linux__
	if (::fallocate(m_handle, FALLOC_FL_KEEP_SIZE, old_rs, new_rs - old_rs) != 0)
	{
		return false;
	}
#else
	if (::posix_fallocate(m_handle, old_rs, new_rs - old_rs) != 0)
	{
		return false;
	}
#endif

	return true;
}

bool sfs::view::set_delete()
{
#ifdef _WIN32
	FILE_DISPOSITION_INFO disp;
	disp.DeleteFileW = TRUE;
	if (!SetFileInformationByHandle(m_handle, FileDispositionInfo, &disp, sizeof(disp)))
	{
		return false;
	}
#elif __linux__
	char path[PATH_MAX + 1]{};
	if (::readlink(("/proc/self/fd/" + std::to_string(m_handle)).c_str(), path, PATH_MAX) == -1)
	{
		return false;
	}

	if (::unlink(path) == -1)
	{
		return false;
	}
#else
	return false;
#endif

	return true;
}

std::uint64_t sfs::view::trunc(std::uint64_t new_size)
{
	// Convert to real filesizes
	const std::uint64_t old_rs = m_count * 4096;
	const std::uint64_t new_rs = new_size / block_size * 4096 + (new_size % block_size ? 4096 : 0);

	// Limit absurd values
	if (old_rs == new_rs || new_size > 1024ull * 1024 * 1024 * 1024 * 1024 /* 1024 TiB */)
	{
		return size();
	}

	// Only use the syscall for shrinkage
#ifdef _WIN32
	FILE_END_OF_FILE_INFO _eof;
	_eof.EndOfFile.QuadPart = new_rs;

	if (new_rs < old_rs && !SetFileInformationByHandle(m_handle, FileEndOfFileInfo, &_eof, sizeof(_eof)))
	{
		return size();
	}
#else
	if (new_rs < old_rs && ::ftruncate(m_fd, new_rs) != 0)
	{
		return size();
	}
#endif

	// Increase file size by writing encrypted zeros
	if (new_rs > old_rs)
	{
		// Zeros
		static constexpr uchar s_zeros[block_size]{};

		// Encrypt zero blocks
		for (std::uint64_t i = old_rs / 4096; i < new_rs / 4096; i++)
		{
			if (!write_block(i, s_zeros))
			{
				return i * block_size;
			}
		}
	}

	// Decrease file size
	if (new_rs < old_rs)
	{
		m_count = new_rs / 4096;
	}

	return new_rs / 4096 * block_size;
}

std::size_t sfs::view::read(std::uint64_t _offset, void* buf, std::size_t size)
{
	std::size_t result = 0;

	for (std::uint64_t offset = _offset; result < size;)
	{
		const std::size_t _mod = offset % block_size;
		const std::size_t _size = std::min(size - result, block_size - _mod);

		if (!read_block(offset / block_size, !buf || _size < block_size ? m_buf : static_cast<uchar*>(buf) + result))
		{
			return result;
		}

		if (buf && _size < block_size)
		{
			std::memcpy(static_cast<uchar*>(buf) + result, m_buf + _mod, _size);
		}

		if (!buf || _size < block_size)
		{
			OPENSSL_cleanse(m_buf, block_size);
		}

		offset += _size;
		result += _size;
	}

	return result;
}

std::size_t sfs::view::write(std::uint64_t _offset, const void* buf, std::size_t size)
{
	std::uint64_t fsize = this->size();
	std::uint64_t fneed = _offset - (_offset % block_size);

	if (fsize < fneed)
	{
		// Limit automatic extension to 1 GiB (offset may be absurd)
		if (fneed - fsize > 1024 * 1024 * 1024)
		{
			return 0;
		}

		// Initialize gap between previous EOF and new write offset
		if (this->trunc(fneed) != fneed)
		{
			return 0;
		}

		fsize = fneed;
	}

	std::size_t result = 0;

	for (std::uint64_t offset = _offset; result < size;)
	{
		const std::size_t _mod = offset % block_size;
		const std::size_t _size = std::min(size - result, block_size - _mod);

		if (offset >= fsize && _size < block_size)
		{
			// New block
			std::memset(m_buf, 0, block_size);
		}
		else if (_size < block_size && !read_block(offset / block_size, m_buf))
		{
			// Partial block overwrite failed
			return result;
		}

		if (buf && _size < block_size)
		{
			std::memcpy(m_buf + _mod, static_cast<const uchar*>(buf) + result, _size);
		}
		else if (offset < fsize || _size == block_size)
		{
			std::memset(m_buf + _mod, 0, _size);
		}

		if (!write_block(offset / block_size, !buf || _size < block_size ? m_buf : static_cast<const uchar*>(buf) + result))
		{
			return result;
		}

		if (!buf || _size < block_size)
		{
			OPENSSL_cleanse(m_buf, block_size);
		}

		offset += _size;
		result += _size;
	}

	return result;
}
