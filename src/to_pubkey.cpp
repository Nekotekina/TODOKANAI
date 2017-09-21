#include "to_pubkey.hpp"
#include "util/endian.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "util/curve25519.hpp"

// Base57 uses: numbers, latin uppercase without 'B', 'D', 'I', 'O', latin lowercase without 'l'
constexpr char s_base57_palette[] = "0123456789ACEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

template <uchar Ch, uchar Pos = 0>
struct base57_lookup
{
	static constexpr uchar value = s_base57_palette[Pos] == Ch ? Pos : base57_lookup<Ch, Pos + 1>::value;
};

template <uchar Ch>
struct base57_lookup<Ch, 57>
{
	static constexpr uchar value = 57;
};

#define XP0(x) base57_lookup<x>::value, base57_lookup<x + 1>::value
#define XP1(x) XP0(x), XP0(x + 2)
#define XP2(x) XP1(x), XP1(x + 4)
#define XP3(x) XP2(x), XP2(x + 8)
#define XP4(x) XP3(x), XP3(x + 16)
#define XP5(x) XP4(x), XP4(x + 32)

static constexpr uchar base57_lut[256] =
{
	XP5(0), XP5(64), XP5(128), XP5(192)
};

#undef XP0
#undef XP1
#undef XP2
#undef XP3
#undef XP4
#undef XP5

std::string to::pubkey::hex() const
{
	static constexpr char s_hex_palette[] = "0123456789abcdef";

	std::string result;
	result.resize(sizeof(m_key) * 2);

	const auto ptr = &result.front();

	for (std::size_t i = 0; i < sizeof(m_key); i++)
	{
		const uchar value = m_key[i];
		ptr[i * 2 + 0] = s_hex_palette[value >> 4];
		ptr[i * 2 + 1] = s_hex_palette[value & 15];
	}

	return result;
}

std::string to::pubkey::base57() const
{
	std::string result;
	result.resize(sizeof(m_key) / 8 * 11);

	const auto ptr = &result.front();

	for (std::size_t i = 0, p = 0; i < sizeof(m_key); i += 8, p += 11)
	{
		// Load block as a big endian 64-bit value
		std::uint64_t value;
		std::be_load(value, m_key + i);

		for (int j = 10; j >= 0; j--)
		{
			ptr[p + j] = s_base57_palette[value % 57];
			value /= 57;
		}
	}

	return result;
}

bool to::pubkey::base57(const char* ptr)
{
	// Base57 encoding: each 64-bit block corresponds to 11 Base57 characters
	static_assert(sizeof(m_key) % 8 == 0, "Unexpected key size (not multiple of 64 bit)");

	// Validate characters
	for (std::size_t i = 0; i < sizeof(m_key) / 8 * 11; i++)
	{
		if (base57_lut[static_cast<uchar>(ptr[i])] >= 57)
		{
			return false;
		}
	}

	for (std::size_t i = 0, p = 0; i < sizeof(m_key); i += 8, p += 11)
	{
		std::uint64_t value = 0;

		for (int j = 0; j < 11; j++)
		{
			value *= 57;
			value += base57_lut[static_cast<uchar>(ptr[p + j])];
		}

		// Store big endian 64-bit value
		std::be_store(m_key + i, value);
	}

	return true;
}

void to::pubkey::generate(const uchar* priv_key)
{
	X25519_public_from_private(m_key, priv_key);
}

bool to::pubkey::secret(const uchar* priv_key, uchar* out_sha512) const
{
	uchar shared_key[32];

	if (X25519(shared_key, priv_key, m_key) != 1 ||
		SHA512(shared_key, sizeof(shared_key), out_sha512) == nullptr)
	{
		OPENSSL_cleanse(shared_key, sizeof(shared_key));
		return false;
	}

	OPENSSL_cleanse(shared_key, sizeof(shared_key));
	return true;
}

bool to::pubkey::encrypt(const void* buf, std::size_t size, uchar* out_cryptobox) const
{
	uchar enc_key[64];
	uchar priv_key[32];
	uchar shared_key[32];

	// Arbitrary size limit
	if (size > 0x10000000)
	{
		return false;
	}

	// Generate random ephemeral private key, compute static-ephemeral shared secret hash it with SHA-512
	if (RAND_bytes(priv_key, sizeof(priv_key)) != 1 ||
		X25519(shared_key, priv_key, m_key) != 1 ||
		SHA512(shared_key, sizeof(shared_key), enc_key) == nullptr)
	{
		return false;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if (!ctx)
	{
		return false;
	}

	// Write ephemeral public key
	X25519_public_from_private(out_cryptobox + 0, priv_key);

	// Initialize derived encryption key, nonce (all zeros), use ephemeral public key as AAD
	static uchar nonce[12] = {0};
	int len;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, enc_key, nonce) != 1 ||
		EVP_EncryptUpdate(ctx, nullptr, &len, out_cryptobox, 32) != 1 ||
		EVP_EncryptUpdate(ctx, out_cryptobox + 32, &len, reinterpret_cast<const uchar*>(buf), static_cast<int>(size)) != 1 ||
		EVP_EncryptFinal_ex(ctx, out_cryptobox + 32 + len, &len) != 1 ||
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out_cryptobox + 32 + size) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	OPENSSL_cleanse(enc_key, sizeof(enc_key));
	OPENSSL_cleanse(priv_key, sizeof(priv_key));
	OPENSSL_cleanse(shared_key, sizeof(shared_key));
	EVP_CIPHER_CTX_free(ctx);
	return true;
}

bool to::pubkey::decrypt(void* buf, std::size_t size, const uchar* priv_key, const uchar* cryptobox)
{
	uchar enc_key[64];

	if (size > 0x10000000 || !reinterpret_cast<const to::pubkey*>(cryptobox)->secret(priv_key, enc_key))
	{
		return false;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if (!ctx)
	{
		return false;
	}

	// Initialize derived encryption key, nonce (all zeros), use ephemeral public key as AAD
	static uchar nonce[12] = {0};
	int len;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, enc_key, nonce) != 1 ||
		EVP_DecryptUpdate(ctx, nullptr, &len, cryptobox, 32) != 1 ||
		EVP_DecryptUpdate(ctx, reinterpret_cast<uchar*>(buf), &len, cryptobox + 32, static_cast<int>(size)) != 1 ||
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uchar*>(cryptobox) + 32 + size) != 1 ||
		EVP_DecryptFinal_ex(ctx, reinterpret_cast<uchar*>(buf) + len, &len) <= 0)
	{
		OPENSSL_cleanse(enc_key, sizeof(enc_key));
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	OPENSSL_cleanse(enc_key, sizeof(enc_key));
	EVP_CIPHER_CTX_free(ctx);
	return true;
}
