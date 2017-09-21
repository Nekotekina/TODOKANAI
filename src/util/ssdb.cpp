#include "ssdb.hpp"
#include <openssl/hmac.h>

ssdb::combined_hash::combined_hash(const void* salt, int len)
	: m_hmac(HMAC_CTX_new())
{
	HMAC_Init_ex(m_hmac, salt, len, EVP_sha512(), nullptr);
}

ssdb::combined_hash::~combined_hash()
{
	HMAC_CTX_free(m_hmac);
}

void ssdb::combined_hash::combine(const void* data, std::size_t len)
{
	uchar hash[64];
	HMAC_Init_ex(m_hmac, nullptr, 0, nullptr, nullptr);
	HMAC_Update(m_hmac, reinterpret_cast<const uchar*>(data), len);
	HMAC_Final(m_hmac, hash, nullptr);

	for (std::size_t i = 0; i < sizeof(m_hash); i++)
	{
		m_hash[i] ^= hash[i];
	}
}

bool ssdb::combined_hash::check(const uchar* src) const
{
	return std::memcmp(m_hash, src, sizeof(m_hash)) == 0;
}

void ssdb::combined_hash::dump(uchar* dst) const
{
	std::memcpy(dst, m_hash, sizeof(m_hash));
}

void ssdb::combined_hash::clear()
{
	std::memset(m_hash, 0, sizeof(m_hash));
}

void ssdb::free_space::add_free(std::uint32_t block, std::uint32_t count)
{
	if (count == 0)
	{
		return;
	}

	auto it = m_free.emplace(block, count).first;

	// Extend if necessary
	if (it->second < count)
	{
		it->second = count;
	}

	// Check overflow
	if (it->second + block < block)
	{
		it->second = UINT32_MAX - block;
	}

	if (it != m_free.begin())
	{
		// Check previous entry
		auto it2 = it; it2--;

		if (it2->first + it2->second >= it->first)
		{
			// Merge with the previous entry
			it2->second += it->second - (it2->first + it2->second - it->first);
			m_free.erase(it);
			it = it2;
		}
	}

	// Check next entry
	auto it3 = it; it3++;

	if (it3 != m_free.end() && it->first + it->second >= it3->first)
	{
		// Merge with the next entry
		it->second += it3->second - (it->first + it->second - it3->first);
		m_free.erase(it3);
	}
}

std::uint32_t ssdb::free_space::get_free(std::uint32_t count)
{
	auto res = m_free.cend();

	// Find the smallest fitting free space
	for (auto it = m_free.cbegin(), end = res; it != end; it++)
	{
		if (it->second >= count)
		{
			if (res == end || res->second > it->second)
			{
				res = it;

				if (res->second == count)
				{
					break;
				}
			}
		}
	}

	if (res == m_free.cend())
	{
		if (m_free.empty())
		{
			// Initialize from default state
			if (count)
			{
				m_free.emplace(count, 0 - count);
			}

			return 0;
		}

		throw std::bad_alloc();
	}

	const std::uint32_t pos = res->first;

	if (const std::uint32_t diff = res->second - count)
	{
		m_free.erase(res);

		// Restore the fragment
		m_free.emplace(pos + count, diff);
	}
	else
	{
		m_free.erase(res);

		// Prevent from restoring the default state
		if (m_free.empty())
		{
			m_free.emplace(0, 0);
		}
	}

	return pos;
}
