#pragma once

#include <map>
#include <unordered_map>
#include <vector>
#include <mutex>
#include "sfs.hpp"
#include "sstl.hpp"
#include "endian.hpp"

extern "C"
{
	typedef struct hmac_ctx_st HMAC_CTX;
}

namespace ssdb
{
	// Three types of blocks:
	// 1) Data begin
	// 2) Data continuation (zero or more blocks of this type follow the beginning block)
	// 3) Terminator (contains combined checksum of valid data sequence identifiers)
	struct block_layout
	{
		// Unique increasing identifier of the block sequence, starts from 1
		std::be_t<std::uint64_t> order;

		// Data size; 0 = terminator; -1 = continuation
		std::be_t<std::uint64_t> size;

		// Reserved
		std::be_t<std::uint64_t> x10, x18;

		// Data
		uchar data[sfs::block_size - 4 * sizeof(std::uint64_t)];
	};

	struct control
	{
		// Current block order (0 - should be assigned and written)
		std::uint64_t order;

		// Loaded or flushed block range, moved to free space after successful flush
		std::uint32_t load_block, load_count;

		// Written block, moved to loaded block after successful flush
		std::uint32_t new_block, new_count;
	};

	constexpr control null_control{};

	// Combined SHA-512 hash
	class combined_hash final
	{
		uchar m_hash[64]{};

		HMAC_CTX* m_hmac{nullptr};

	public:
		combined_hash(const void* salt, int len);

		combined_hash(const combined_hash&) = delete;

		~combined_hash();

		// Hash and combine
		void combine(const void* data, std::size_t len);

		// Compare with hash in question
		bool check(const uchar* src) const;

		// Read hash value directly
		void dump(uchar* dst) const;

		// Set null value
		void clear();

		// Hash size
		static constexpr std::size_t size()
		{
			return sizeof(m_hash);
		}
	};

	struct free_space
	{
	protected:
		// Default state (empty) means 2^32 free blocks
		std::map<std::uint32_t, std::uint32_t> m_free;

		void add_free(std::uint32_t block, std::uint32_t count);

		std::uint32_t get_free(std::uint32_t count);
	};

	template <typename K, typename T, typename H = std::hash<K>>
	class umap final : free_space
	{
		std::unordered_map<K, std::pair<control, T>, H> m_map;

		std::unique_ptr<sfs::view> m_data;

		// Error bits
		std::uint32_t m_error{0};

		// Block index of the previous terminator
		std::uint32_t m_lastf;

		// Order of the last update
		std::uint64_t m_order;

		// Order of the last flush, flush is required if (m_order > m_flush)
		std::uint64_t m_flush;

		// Combined SHA-512 hash of the all order indices in use (HMAC(key, 33) ^ HMAC(key, 444) ^ ...)
		combined_hash m_hash;

		// Note: should not use shared mutex
		std::mutex m_mutex;

		// Add/remove order hash
		void xor_order(std::uint64_t order, std::uint64_t pos)
		{
			std::be_t<std::uint64_t> data[2]{order, pos};
			m_hash.combine(+data, sizeof(data));
		}

		void reload()
		{
			const std::uint32_t count = static_cast<std::uint32_t>(m_data->size() / sfs::block_size);

			uchar last_hash[combined_hash::size()]{};

			std::vector<uchar> buf;

			m_map.clear();
			m_free.clear();
			m_hash.clear();
			m_order = 0;
			m_lastf = -1;
			add_free(count, 0 - count);

			block_layout sbuf;

			for (std::uint32_t i = 0; i < count; i++)
			{
				if (!m_data->read_block(i, reinterpret_cast<uchar*>(&sbuf)))
				{
					m_error |= 1;
					add_free(i, 1);
					continue;
				}

				const std::uint64_t _order = sbuf.order;
				const std::uint32_t _block = i;

				if (_order - 1 >= INT64_MAX)
				{
					m_error |= 2;
					add_free(i, 1);
					continue;
				}

				if (sbuf.size >= (1u << 31))
				{
					if (sbuf.size != -1)
					{
						m_error |= 2;
					}

					add_free(i, 1);
					continue;
				}

				if (m_flush != -1 && _order > m_order)
				{
					// Remember max order
					m_order = _order;
				}

				if (_order > m_flush)
				{
					m_error |= 4;
					add_free(i, 1);
					continue;
				}

				// Get record size
				std::size_t size = static_cast<std::size_t>(sbuf.size);

				if (size == 0)
				{
					// Terminator
					if (m_flush == -1 && _order > m_order)
					{
						add_free(m_lastf, 1);
						std::memcpy(last_hash, sbuf.data, sizeof(last_hash));
						m_order = _order;
						m_lastf = _block;
					}
					else if (m_flush == _order)
					{
						std::memcpy(last_hash, sbuf.data, sizeof(last_hash));
						m_lastf = _block;
					}
					else
					{
						add_free(i, 1);
					}

					continue;
				}

				buf.clear();
				buf.reserve(size);
				buf.insert(buf.end(), sbuf.data, sbuf.data + std::min(size, sizeof(sbuf.data)));
				size -= std::min(size, sizeof(sbuf.data));

				for (std::uint32_t j = i + 1; size > sizeof(sbuf.data) && j < count; j++, i++)
				{
					if (!m_data->read_block(i, reinterpret_cast<uchar*>(&sbuf)) || sbuf.order != _order || sbuf.size != -1)
					{
						m_error |= 8;
						add_free(_block, (i + 1) - _block);
						break;
					}

					buf.insert(buf.end(), sbuf.data, sbuf.data + std::min(size, sizeof(sbuf.data)));
					size -= std::min(size, sizeof(sbuf.data));
				}

				if (size)
				{
					m_error |= 16;
					continue;
				}

				sstl::context_data ctx(sstl::context_type::reading, reinterpret_cast<sstl::byte*>(buf.data()), buf.size());

				K key{};
				ctx.traverse<sstl::context_type::reading>(key);

				auto& pair = m_map.emplace(std::piecewise_construct, std::forward_as_tuple(std::move(key)), std::forward_as_tuple()).first->second;
				auto& ctrl = pair.first;

				if (ctrl.order < _order)
				{
					if (ctrl.order)
					{
						// Overwrite the block
						xor_order(ctrl.order, ctrl.load_block);
						add_free(ctrl.load_block, ctrl.load_count);
					}

					ctrl.order      = _order;
					ctrl.load_block = _block;
					ctrl.load_count = (i + 1) - _block;
					pair.second     = {};
					ctx.traverse<sstl::context_type::reading>(pair.second);
					xor_order(sbuf.order, _block);
				}
				else
				{
					add_free(_block, (i + 1) - _block);
				}
			}

			if (m_flush == -1)
			{
				// Complete first (optimistic) attempt
				m_flush = m_order;

				if (!m_hash.check(last_hash))
				{
					return reload();
				}
			}
			else if (m_flush == -2)
			{
				// Complete third attempt (heavy damage)
				m_flush = 0;
				m_error |= 32;
			}
			else if (!m_hash.check(last_hash))
			{
				m_flush = -2;
				return reload();
			}
			else
			{
				// Complete second attempt (rollback unfinished modifications)
				// Last order is lie
				m_flush = m_order;
			}
		}

		void dirty(std::pair<const K, std::pair<control, T>>& item)
		{
			auto& ctrl = item.second.first;

			if (ctrl.order)
			{
				xor_order(ctrl.order, ctrl.new_count ? ctrl.new_block : ctrl.load_block);
				ctrl.order = 0;
			}
		}

		void write(std::pair<const K, std::pair<control, T>>& item)
		{
			auto& ctrl = item.second.first;

			// Initialize data
			std::vector<uchar> buf = sstl::save([&](auto ctx)
			{
				ctx(const_cast<K&>(item.first));
				ctx(item.second.second);
			});

			// Get number of blocks required
			std::uint32_t count = static_cast<std::uint32_t>(buf.size() / sizeof(block_layout::data));

			if (buf.size() % sizeof(block_layout::data))
			{
				count += 1;
			}

			// Update order
			dirty(item);
			ctrl.order = ++m_order;

			// Update blocks
			if (ctrl.new_count != count)
			{
				add_free(ctrl.new_block, ctrl.new_count);
				ctrl.new_block = get_free(count);
				ctrl.new_count = count;
			}

			xor_order(ctrl.order, ctrl.new_block);

			block_layout sbuf{};

			for (std::uint32_t i = 0; i < count; i++)
			{
				sbuf.order = ctrl.order;

				if (i == 0)
				{
					sbuf.size = buf.size();
				}
				else
				{
					sbuf.size = -1;
				}

				std::memcpy(sbuf.data, buf.data() + i * sizeof(sbuf.data), std::min(buf.size() - i * sizeof(sbuf.data), sizeof(sbuf.data)));

				if (i && i == count - 1)
				{
					std::memset(sbuf.data + buf.size() - i * sizeof(sbuf.data), 0, count * sizeof(sbuf.data) - buf.size());
				}

				if (!m_data->write_block(ctrl.new_block + i, reinterpret_cast<uchar*>(&sbuf)))
				{
					add_free(ctrl.new_block, ctrl.new_count);
					xor_order(ctrl.order, ctrl.new_block);
					ctrl.new_block = 0;
					ctrl.new_count = 0;
					ctrl.order = 0;
					m_error |= 64;
					m_order--;
					break;
				}
			}
		}

		void finalize()
		{
			if (m_order <= m_flush)
			{
				return;
			}

			for (auto& item : m_map)
			{
				if (!item.second.first.order)
				{
					write(item);
				}
			}

			m_data->flush();

			// Write terminator
			const std::uint32_t new_pos = get_free(1);

			block_layout term{};
			term.order = ++m_order;
			m_hash.dump(term.data);

			if (!m_data->write_block(new_pos, reinterpret_cast<uchar*>(&term)))
			{
				m_order--;
				m_error |= 128;
				add_free(new_pos, 1);
				return;
			}

			// Second flush (TODO: possibly avoid by combining with the following writes)
			m_data->flush();
			add_free(m_lastf, 1);
			m_lastf = new_pos;
			m_flush = m_order;

			// Update free space
			for (auto& item : m_map)
			{
				control& ctrl = item.second.first;

				if (ctrl.new_count)
				{
					add_free(ctrl.load_block, ctrl.load_count);
					ctrl.load_block = ctrl.new_block;
					ctrl.load_count = ctrl.new_count;
					ctrl.new_block = 0;
					ctrl.new_count = 0;
				}
			}
		}

	public:
		umap(const void* salt, int len)
			: m_hash(salt, len)
		{
		}

		~umap()
		{
			if (m_data)
			{
				finalize();
			}
		}

		void init(std::unique_ptr<sfs::view> view)
		{
			if (view)
			{
				m_data = std::move(view);
			}

			if (m_data)
			{
				m_flush = -1;
				reload();

				if (m_lastf == -1)
				{
					finalize();
				}
			}
		}

		class reader
		{
		protected:
			umap& m_ref;

		public:
			reader(umap& ref)
				: m_ref(ref)
			{
			}

			const T* operator [](const K& key) const
			{
				const auto found = m_ref.m_map.find(key);

				if (found == m_ref.m_map.end())
				{
					return nullptr;
				}

				return &found->second.second;
			}

			class iterator
			{
				typename std::unordered_map<K, std::pair<control, T>, H>::const_iterator m_it;

			public:
				iterator(decltype(m_it) it)
					: m_it(std::move(it))
				{
				}

				bool operator ==(const iterator& rhs) const
				{
					return m_it == rhs.m_it;
				}

				bool operator !=(const iterator& rhs) const
				{
					return m_it != rhs.m_it;
				}

				struct ref_pair
				{
					const K& first;
					const T& second;
				}
				operator *() const
				{
					return {m_it->first, m_it->second.second};
				}

				auto& operator ++()
				{
					++m_it;
					return *this;
				}
			};

			iterator begin() const
			{
				return {m_ref.m_map.cbegin()};
			}

			iterator end() const
			{
				return {m_ref.m_map.cend()};
			}
		};

		template <typename F>
		auto read(F&& read_op)
		{
			std::lock_guard<std::mutex> lock(m_mutex);

			return std::forward<F>(read_op)(reader{*this});
		}

		class writer
		{
		protected:
			umap& m_ref;

			bool m_modify = false;
			bool m_flush;

		public:
			writer(umap& ref, bool flush = false)
				: m_ref(ref)
				, m_flush(flush)
			{
			}

			~writer()
			{
				if (m_modify)
				{
					for (auto& item : m_ref.m_map)
					{
						if (!item.second.first.order)
						{
							m_ref.write(item);
						}
					}
				}

				if (m_flush)
				{
					m_ref.finalize();
				}
			}

			T* operator [](const K& key)
			{
				const auto found = m_ref.m_map.find(key);

				if (found == m_ref.m_map.end())
				{
					return nullptr;
				}

				m_modify = true;
				m_ref.dirty(*found);

				return &found->second.second;
			}

			template <bool Modify = true, typename KK, typename... Args>
			std::conditional_t<Modify, T*, const T*> add(KK&& key, Args&&... args)
			{
				const auto res = m_ref.m_map.emplace(
					std::piecewise_construct,
					std::forward_as_tuple(std::forward<KK>(key)),
					std::forward_as_tuple(
						std::piecewise_construct,
						std::forward_as_tuple(null_control),
						std::forward_as_tuple(std::forward<Args>(args)...)));

				if (Modify || res.second)
				{
					m_modify = true;
					m_ref.dirty(*res.first);
				}

				return &res.first->second.second;
			}

			const T* get(const K& key) const
			{
				const auto found = m_ref.m_map.find(key);

				if (found == m_ref.m_map.end())
				{
					return nullptr;
				}

				return &found->second.second;
			}
		};

		template <typename F>
		auto write(F&& write_op)
		{
			std::lock_guard<std::mutex> lock(m_mutex);

			return std::forward<F>(write_op)(writer{*this});
		}

		template <typename F>
		auto flush(F&& write_op)
		{
			std::lock_guard<std::mutex> lock(m_mutex);

			return std::forward<F>(write_op)(writer{*this, true});
		}

		void flush()
		{
			std::lock_guard<std::mutex> lock(m_mutex);

			finalize();
		}
	};

}
