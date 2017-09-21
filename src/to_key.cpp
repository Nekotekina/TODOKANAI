#include "to_key.hpp"
#include "util/sfs.hpp"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <cmath>

#ifdef _WIN32
#define NOMINMAX
#include <Windows.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

extern bool gui_warn(const char*);
extern void gui_fatal(const char*);

namespace
{
	struct dict_word
	{
		const char* word;
		std::size_t size;

		template <std::size_t N>
		constexpr dict_word(const char(&word)[N])
			: word(word)
			, size(N - 1)
		{
			static_assert(N - 1 <= 16, "dict_word error: string is too long");
		}
	};

	struct dict_info
	{
		const dict_word* dict;
		std::size_t dict_length;
		const char* dict_name;
		char delim;

		template <std::size_t N>
		constexpr dict_info(const dict_word(&dict)[N], char delim, const char* name)
			: dict(dict)
			, dict_length(N)
			, dict_name(name)
			, delim(delim)
		{
		}
	};
}

// Characters removed: 'l', 'B', 'D', 'I', 'O'
constexpr dict_word s_dict_latin[] =
{
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
	"g", "h", "i", "j", "k", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w",
	"x", "y", "z", "A", "C", "E", "F", "G", "H", "J", "K", "L", "M", "N", "P", "Q",
	"R", "S", "T", "U", "V", "W", "X", "Y", "Z", //"+", "=", "-", "%", "*", ".", ":",
};

constexpr dict_word s_dict_numbers[]
{
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
};

// Characters removed: 'б', 'ё', 'л', 'ъ', 'ь', 'В', 'Ё', 'З', 'Л', 'О', 'Ъ', 'Ь'
constexpr dict_word s_dict_cyrillic[] =
{
	u8"0", u8"1", u8"2", u8"3", u8"4", u8"5", u8"6", u8"7", u8"8", u8"9", u8"а", u8"в", u8"г", u8"д", u8"е", u8"ж",
	u8"з", u8"и", u8"й", u8"к", u8"м", u8"н", u8"о", u8"п", u8"р", u8"с", u8"т", u8"у", u8"ф", u8"х", u8"ц", u8"ч",
	u8"ш", u8"щ", u8"ы", u8"э", u8"ю", u8"я", u8"А", u8"Б", u8"Г", u8"Д", u8"Е", u8"Ж", u8"И", u8"Й", u8"К", u8"М",
	u8"Н", u8"П", u8"Р", u8"С", u8"Т", u8"У", u8"Ф", u8"Х", u8"Ц", u8"Ч", u8"Ш", u8"Щ", u8"Ы", u8"Э", u8"Ю", u8"Я",
};

constexpr dict_info s_dicts[] =
{
	{ s_dict_latin, 0, "Latin" },
	{ s_dict_numbers, 0, "PIN" },
	{ s_dict_cyrillic, 0, "Cyrillic" },
};

std::size_t to::master_key::dict_count()
{
	return sizeof(s_dicts) / sizeof(s_dicts[0]);
}

std::string to::master_key::dict_name(std::size_t dict_id)
{
	if (dict_id < dict_count())
	{
		std::string result = s_dicts[dict_id].dict_name;
		result += ", ex.: ";

		// Generate password example
		const int dstr = dict_strength(dict_id);
		const int size = 6400 / dstr + (6400 % dstr ? 1 : 0);

		for (int i = 0; i < size; i++)
		{
			std::uint32_t rand;
			RAND_bytes(reinterpret_cast<uchar*>(&rand), sizeof(rand));
			rand %= s_dicts[dict_id].dict_length;
			result += s_dicts[dict_id].dict[rand].word;
		}

		return result;
	}

	return {};
}

int to::master_key::dict_strength(std::size_t dict_id)
{
	if (dict_id < dict_count())
	{
		return static_cast<int>(std::trunc(std::log2(s_dicts[dict_id].dict_length) * 100));
	}

	return 0;
}

to::master_key::master_key(const uchar* secret, std::size_t size)
	: master_key({})
{
	init(secret, size);
}

to::master_key::master_key(const std::string& key_path)
	: m_hmac(HMAC_CTX_new())
	, m_key_path(key_path)
#ifdef _WIN32
	, m_key_file(INVALID_HANDLE_VALUE)
#else
	, m_key_file(-1)
#endif
{
}

to::master_key::~master_key()
{
	reset();
	HMAC_CTX_free(m_hmac);
}

void to::master_key::reset()
{
	if (m_pass)
	{
		OPENSSL_clear_free(m_pass, m_pass_size + 1);
		m_pass = nullptr;
		m_pass_size = 0;
	}

	OPENSSL_cleanse(m_result, sizeof(m_result));
	OPENSSL_cleanse(m_secret, sizeof(m_secret));
	HMAC_CTX_reset(m_hmac);
#ifdef _WIN32
	::CloseHandle(m_key_file);
	m_key_file = INVALID_HANDLE_VALUE;
#else
	::close(m_key_file);
	m_key_file = -1;
#endif
}

void to::master_key::init(const char* pass, std::size_t len)
{
	reset();

	// Fixed salt is usually insecure, however, it allows obtaining derived keys in a stateless manner.
	static constexpr uchar static_salt[64] =
	{
		0x06, 0xCA, 0x7E, 0xA7, 0x42, 0x01, 0x65, 0xBB, 0xC1, 0xEF, 0xBB, 0x02, 0x21, 0x5B, 0x90, 0xCF,
		0x2F, 0x45, 0x53, 0x90, 0x75, 0x2D, 0x1C, 0x21, 0x6F, 0x72, 0x36, 0xF4, 0xD4, 0x12, 0xE7, 0xFA,
		0x4A, 0xDB, 0xB1, 0x52, 0x2B, 0x6C, 0xCE, 0xB5, 0x55, 0xF6, 0xA4, 0x41, 0x02, 0xFA, 0x42, 0x0C,
		0x15, 0xB0, 0xAF, 0x6C, 0x35, 0x16, 0x53, 0x0A, 0xA8, 0x9B, 0x43, 0xFA, 0x86, 0xC5, 0xAA, 0xBE,
	};

	// Selected scrypt params use 512 MB of memory and should take about 1-2 sec of single-core load with a typical desktop CPU
	while (EVP_PBE_scrypt(pass, len, static_salt, sizeof(static_salt), 512 * 1024, 8, 1, 600 * 1024 * 1024, m_secret, sizeof(m_secret)) == 0)
	{
		if (!gui_warn("Out of memory. This operation requires 512 MiB of free memory."))
		{
			std::terminate();
		}
	}

	init(m_secret, sizeof(m_secret));
	set_pass(pass, len);
}

void to::master_key::init(const uchar* secret, std::size_t size)
{
	if (!secret || !size || HMAC_Init_ex(m_hmac, secret, static_cast<int>(size), EVP_sha512(), nullptr) != 1)
	{
		gui_fatal("HMAC init failed");
		std::terminate();
	}
}

const uchar* to::master_key::get(const char* info, std::size_t info_size)
{
	// Get info string length
	const std::size_t size = info_size == -1 ? std::strlen(info) : info_size;

	if (HMAC_Init_ex(m_hmac, nullptr, 0, nullptr, nullptr) != 1 ||
		HMAC_Update(m_hmac, reinterpret_cast<const uchar*>(info), size) != 1 ||
		HMAC_Final(m_hmac, m_result, nullptr) != 1)
	{
		return nullptr;
	}

	return m_result;
}

void to::master_key::generate(const std::string& prefix, std::size_t dict_id, int len)
{
	// Allocate using max dict_word size + delim + null terminator
	const auto ptr = static_cast<char*>(OPENSSL_zalloc(prefix.size() + len * 17));
	std::memcpy(ptr, prefix.c_str(), prefix.size());

	{
		auto pass = ptr + prefix.size();

		for (int i = 0; i < len; i++)
		{
			if (s_dicts[dict_id].delim && i > 0)
			{
				*pass++ = s_dicts[dict_id].delim;
			}

			std::uint32_t rand;
			RAND_bytes(reinterpret_cast<uchar*>(&rand), sizeof(rand));
			rand %= s_dicts[dict_id].dict_length;
			const auto& word = s_dicts[dict_id].dict[rand];
			std::memcpy(pass, word.word, word.size);
			pass += word.size;
		}

		*pass = 0;
	}

	const auto pass_len = std::strlen(ptr);
	init(ptr, pass_len);
	OPENSSL_clear_free(ptr, pass_len);
}

bool to::master_key::load()
{
	reset();

#ifdef _WIN32
	m_key_file = ::CreateFileW(sfs::wpath(m_key_path).get(), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ENCRYPTED, 0);

	DWORD nread;

	if (m_key_file != INVALID_HANDLE_VALUE && ::ReadFile(m_key_file, m_secret, sizeof(m_secret), &nread, 0) && nread == sizeof(m_secret))
#else
	m_key_file = ::open(key_path.c_str(), O_RDONLY);

	if (m_key_file != -1 && ::read(m_key_file, m_secret, sizeof(m_secret)) == sizeof(m_secret))
#endif
	{
		init(m_secret, sizeof(m_secret));
		return true;
	}

	reset();
	return false;
}

void to::master_key::save()
{
#ifdef _WIN32
	m_key_file = ::CreateFileW(sfs::wpath(m_key_path).get(), GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ENCRYPTED, 0);

	DWORD nwritten;

	if (m_key_file == INVALID_HANDLE_VALUE || !::WriteFile(m_key_file, m_secret, sizeof(m_secret), &nwritten, 0) || nwritten != sizeof(m_secret))
#else
	m_key_file = ::open(key_path.c_str(), O_RDONLY);

	if (key_file == -1 || ::write(key_file, m_secret, sizeof(m_secret)) != sizeof(m_secret))
#endif
	{
		gui_fatal("Failed to create key file. Check permissions and try again.");
		std::terminate();
	}
}

void to::master_key::set_pass(const char* pass, std::size_t len)
{
	if (m_pass)
	{
		OPENSSL_clear_free(m_pass, m_pass_size + 1);
	}

	m_pass = static_cast<char*>(OPENSSL_zalloc(len + 1));
	std::memcpy(m_pass, pass, len);
	m_pass[len] = '\0';
	m_pass_size = len;
}
