#pragma once

// Encrypted container with strong authenticated encryption, consists of fixed-size blocks.
// Allows random reading and writing data in 4096 byte chunks with data size of 4064 bytes.
// Cipher: AES-256-GCM with non-standard nonce length (16), as implemented in OpenSSL.
// 1) Prologue: random 128 bit nonce
// 2) (NOT STORED) Additional authenticated data for GCM
// 2.1) BE 64-bit unique storage identifier, provided externally
// 2.2) BE 64-bit block index in the storage, it prevents moving blocks within the storage
// 3) (4096 - 32) bytes of encrypted data.
// 4) Epilogue: 128 bit auth tag
// Blocks are normally indistinguishable from random data. The key must be externally known.

#include <memory>
#include <vector>
#include <string>
#include "endian.hpp"

extern "C"
{
	typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
}

using uchar = unsigned char;

namespace sfs
{
	// Encrypted block payload size
	constexpr std::size_t block_size = 4096 - 32;

	// Encrypted container
	class view
	{
#ifdef _WIN32
		using handle = void*;
#else
		using handle = int;
#endif
		// Native file handle
		const handle m_handle;

		// Crypto context (encryption)
		EVP_CIPHER_CTX* m_enc;

		// Crypto context (decryption)
		EVP_CIPHER_CTX* m_dec;

		// Actual file size in blocks
		std::uint64_t m_count;

		struct block_aad final
		{
			std::be_t<std::uint64_t> ident; // Current block identifier (usually 0)
			std::be_t<std::uint64_t> index; // Current block index
		};

		// Buffer for a single plaintext block
		uchar m_buf[block_size];

	public:
		view(handle&& _handle, const uchar* aes256_key);

		view(const view&) = delete;

		~view();

		// Get current effective storage size (multiple of block_size)
		std::uint64_t size() const
		{
			return m_count * block_size;
		}

		// Get current effective storage size in blocks
		std::uint64_t count() const
		{
			return m_count;
		}

		// Ensure disc writes
		void flush();

		// Allocate storage without changing the size (may do nothing)
		bool alloc(std::uint64_t future_size);

		// Set to automatically delete file on close
		bool set_delete();

		bool read_block(std::uint64_t block, uchar* buf, std::uint64_t ident = 0);
		bool write_block(std::uint64_t block, const uchar* buf, std::uint64_t ident = 0);

		// Resize storage (returns new size, multiple of block_size)
		std::uint64_t trunc(std::uint64_t new_size);

		std::size_t read(std::uint64_t offset, void* buf, std::size_t size);
		std::size_t write(std::uint64_t offset, const void* buf, std::size_t size);
	};

#ifdef _WIN32
	// Convert UTF-8 path to UTF-16
	std::unique_ptr<wchar_t[]> wpath(const std::string& utf8_path);
#endif

	// Try to open an archive file (UTF-8 path)
	std::unique_ptr<view> make_view(const std::string& path, const uchar* aes256_key);

	// Get list of files or directories in the directory (UTF-8 path)
	std::vector<std::string> find_all(const std::string& path, bool directories = false);
}
