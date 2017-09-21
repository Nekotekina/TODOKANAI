#pragma once

#include <string>
#include <cstdint>
#include <cstring>
#include <functional>

using uchar = unsigned char;

namespace to
{
	// X25519 public key
	class pubkey
	{
		// Public key data
		uchar m_key[32];

	public:
		pubkey() = default;

		// TODO: randomize the method of getting the hash
		std::size_t std_hash() const
		{
			return reinterpret_cast<const std::size_t&>(m_key);
		}

		// Convert to Hex (lowercase)
		std::string hex() const;

		// Convert to Base57
		std::string base57() const;

		// Set public key from Base57
		bool base57(const char* ptr);

		// Set public key from private key
		void generate(const uchar* priv_key);

		bool operator ==(const to::pubkey& rhs) const
		{
			return std::memcmp(m_key, rhs.m_key, 32) == 0;
		}

		bool operator !=(const to::pubkey& rhs) const
		{
			return std::memcmp(m_key, rhs.m_key, 32) != 0;
		}

		bool operator <(const to::pubkey& rhs) const
		{
			return std::memcmp(m_key, rhs.m_key, 32) < 0;
		}

		bool operator >(const to::pubkey& rhs) const
		{
			return std::memcmp(m_key, rhs.m_key, 32) > 0;
		}

		// Compute shared secret
		bool secret(const uchar* priv_key, uchar* out_sha512) const;

		// Encrypt anonymous cryptobox (cryptobox size = size + 32 + 16, AES-256-GCM)
		bool encrypt(const void* buf, std::size_t size, uchar* out_cryptobox) const;

		// Decrypt anonymous cryptobox (cryptobox size = size + 32 + 16, AES-256-GCM)
		static bool decrypt(void* buf, std::size_t size, const uchar* priv_key, const uchar* cryptobox);

		using serialize_copy = void;
	};
}

namespace std
{
	template <>
	struct hash<to::pubkey>
	{
		std::size_t operator()(const to::pubkey& key) const
		{
			return key.std_hash();
		}
	};
}
