#pragma once

// Simple compact serialization support tool for C++ standard library.
// An arbitrary class must provide `serialize` template method with context arg:
// `template <typename S> void serialize(S ctx) { ctx(a, b, c); }`
// This function is called to (load|probe|write) specified elements in specified order.
// The relative order of elements and their types shall be preserved across versions.
// To delete element, it must be replaced with `null` element.
// Keeping the element structure intact allows to maintain some level of compatibility:
// 1) Loading older data in newer versions with default values for missing elements.
// 2) Loading newer data in older versions with all unrecognized elements ignored.
// Alternatively, any POD class may provide `using serialize_copy = void;` magic typedef.
// This is less safe, since it will be stored and loaded as a blackbox byte sequence.

/*
struct example
{
	int a;
	bool b;
	//bool c; // obsolete since version 0.999999999
	bool d;
	float c;

	template <typename S>
	void serialize(S ctx)
	{
		ctx(a, b); // equal to ctx(a); ctx(b);
		ctx.null(); // bool c; null placeholder
		ctx(d);
		ctx.name("C");
		ctx(c); // added in version 1.000000000001
	}
};
*/

/*
Format description:
u8 --- 2's complement 8-bit integer (byte)
u32 --- 2's complement big-endian 32-bit integer or single-precision float
u64 --- 2's complement big-endian 64-bit integer or double-precision float
*** --- variable amount of bytes

doc ::= val doc --- recursive document definition (simple list of values)
      | "\x00" --- document terminator (one level)
      | --- document terminator (EOF, all levels)
val ::= "\x01" doc --- document value
      | "\x02" --- false value (bool), compact "zero" value or empty container
      | "\x03" --- true value (bool)
      | "\x04" u8 --- u8 value
      | "\x05" u8 *** --- u8 size + buffer
      | "\x06" u32 --- u32 value
      | "\x07" u32 *** --- u32 size + buffer
      | "\x08" u64 --- u64 value
      | "\x09" u64 *** --- u64 size + buffer
      | "\x0A"..."\x1E" --- reserved (abort reading)
      | "\x1F" --- null value (force skip)
      | "\x20"..."\xFF" val --- value with metadata string
      | --- no value, could be metadata at the end of a doc

Implemented C++ types:

Simple types (is_arithmetic | is_enum):
 - appropriate u8, u32, or u64 value, or sized buffer

std::unique_ptr:
std::shared_ptr:
 - null value (workaround; there is no way to know how to save/load the objects automatically)

std::array of simple type:
std::vector of simple type:
std::basic_string<SimpleType>:
 - sized buffer

std::bitset<N>:
 - compressed sized buffer

std::array for complex types:
std::deque:
 - document with every element

std::vector for complex types:
std::basic_string for complex types:
 - document with count and every element

std::set:
std::multiset:
std::unordered_set:
std::unordered_multiset:
 - document with count and every key

std::map:
std::multimap:
std::unordered_map:
std::unordered_multimap:
 - document with count and every key/value interleaved

C arrays are not supported in favor of std::array<>.
Other containers are not supported because.
C pointers are not supported in favor of what the hell?
Support for other types may be added later:

std::array<bool,N>
std::vector<bool>
 - compressed buffer (not implemented)

std::pair
std::tuple
 - elements in original order (not implemented)

std::optional
 - value or null

std::variant
 - type index, value
*/

#include <type_traits>
#include <functional>
#include <vector>
#include <string>
#include <array>
#include <deque>
#include <set>
#include <unordered_set>
#include <map>
#include <unordered_map>
#include <memory>
#include <list>
#include <forward_list>
#include <bitset>
#include <mutex>
#include <algorithm>
#include "endian.hpp"

using uchar = unsigned char;

namespace sstl
{
	// Helper byte type and constants
	enum class byte : uchar
	{
		terminator = 0x00,
		document   = 0x01,
		bit_false  = 0x02,
		bit_true   = 0x03,
		u8_value   = 0x04,
		u8_sized   = 0x05,
		u32_value  = 0x06,
		u32_sized  = 0x07,
		u64_value  = 0x08,
		u64_sized  = 0x09,

		null_value = 0x1f, // Max, 0x20+ is metadata
	};

	// Context operation
	enum class context_type
	{
		reading,
		probing,
		writing,
	};

	// Helper size_t wrapper (not POD)
	struct size_type
	{
		std::size_t value = 0;

		constexpr size_type() = default;

		constexpr size_type(std::size_t size)
			: value(size)
		{
		}

		constexpr byte type_sized() const
		{
			return value < 256 ? byte::u8_sized : value <= UINT32_MAX ? byte::u32_sized : byte::u64_sized;
		}

		constexpr byte type_value() const
		{
			return value < 256 ? byte::u8_value : value <= UINT32_MAX ? byte::u32_value : byte::u64_value;
		}
	};

	template <typename T, typename = void>
	struct is_simple
	{
		using complex = void;
	};

	template <>
	struct is_simple<bool, void>
	{
		// Special case (neither simple nor complex) (TODO)
	};

	template <typename T>
	struct is_simple<T, std::enable_if_t<std::is_arithmetic<T>::value || std::is_enum<T>::value>>
	{
		using simple = void;
		using data_type = std::be_t<T, 1>;
	};

	template <typename T>
	struct is_simple<T, typename T::serialize_copy>
	{
		static_assert(std::is_standard_layout<T>::value, "Invalid serialize_copy type (must be standard layout)");

		using simple = void;
		using data_type = T;
	};

	template <typename T>
	struct is_simple<T, typename T::serialize_container>
	{
		using simple_container = void;
		using complex = void;

		static void resize(T& ct, std::size_t size)
		{
			ct.clear();
			ct.resize(size);
		}
	};

	template <typename T, std::size_t N>
	struct is_simple<std::array<T, N>, typename is_simple<T>::simple>
	{
		using simple_container = void;
		using complex = void;

		static void resize(std::array<T, N>& ct, std::size_t size)
		{
			ct.fill({});
		}
	};

	template <typename T, typename A>
	struct is_simple<std::vector<T, A>, typename is_simple<T>::simple>
	{
		using simple_container = void;
		using complex = void;

		static void resize(std::vector<T, A>& ct, std::size_t size)
		{
			ct.clear();
			ct.resize(size);
		}
	};

	template <typename T, typename R, typename A>
	struct is_simple<std::basic_string<T, R, A>, typename is_simple<T>::simple>
	{
		using simple_container = void;
		using complex = void;

		static void resize(std::basic_string<T, R, A>& ct, std::size_t size)
		{
			ct.clear();
			ct.resize(size);
		}
	};

	template <context_type Type, typename T, typename = void>
	struct traverse;

	struct context_data
	{
		using ptr_type = byte*;

		context_data(context_type type, ptr_type begin = {}, std::size_t size = 0)
			: begin(begin)
			, end(begin + size)
			, psize(size)
		{
			if (type == context_type::reading)
			{
				psize = 0;
			}
		}

		// Data begin
		ptr_type begin;

		// Data end
		const ptr_type end;

		// Current size (probing); current recursion level (reading)
		std::size_t psize;

		// Get remaining size
		std::size_t remaining() const
		{
			return static_cast<std::size_t>(end - begin);
		}

		// Get max recursion level
		static constexpr std::size_t max_level()
		{
			return 128;
		}

		// Read data (raw)
		void read(void* out, std::size_t _size)
		{
			// Check EOF
			if (remaining() >= _size)
			{
				std::memcpy(out, begin, _size);
				begin += _size;
			}
			else
			{
				begin = end;
			}
		}

		// Read data (raw)
		template <typename T>
		T read()
		{
			T out;
			read(&out, sizeof(T));
			return out;
		}

		// Read size and check against remaining data size
		std::size_t read_size(byte _type)
		{
			if (_type == byte::u8_value || _type == byte::u8_sized)
			{
				const auto size8 = read<uchar>();

				if (remaining() >= size8)
				{
					return size8;
				}
			}

			if (_type == byte::u32_value || _type == byte::u32_sized)
			{
				const std::uint32_t size32 = read<std::be_t<std::uint32_t, 1>>();

				if (remaining() >= size32)
				{
					return size32;
				}
			}

			if (_type == byte::u64_value || _type == byte::u64_sized)
			{
				const std::uint64_t size64 = read<std::be_t<std::uint64_t, 1>>();

				if (remaining() >= size64)
				{
					return static_cast<std::size_t>(size64);
				}
			}

			// Size overflow: abort
			begin = end;
			return 0;
		}

		// Skip current document specified number of times (if zero, skip one value)
		__declspec(noinline) void skip(std::size_t level)
		{
			while (begin < end && (level || *begin != byte::terminator))
			{
				switch (byte _b = *begin++)
				{
				case byte::terminator:
				{
					level -= 1;
					break;
				}
				case byte::document:
				{
					level += 1;
					break;
				}
				case byte::null_value:
				case byte::bit_false:
				case byte::bit_true:
				{
					break;
				}
				case byte::u8_value:
				{
					read<uchar>();
					break;
				}
				case byte::u32_value:
				{
					read<std::be_t<std::uint32_t, 1>>();
					break;
				}
				case byte::u64_value:
				{
					read<std::be_t<std::uint64_t, 1>>();
					break;
				}
				case byte::u8_sized:
				case byte::u32_sized:
				case byte::u64_sized:
				{
					begin += read_size(_b);
					break;
				}
				default:
				{
					if (_b < byte::null_value)
					{
						// Reserved bytes: abort
						begin = end;
						return;
					}

					// Skip metadata
					continue;
				}
				}

				if (level == 0)
				{
					return;
				}
			}
		}

		// Skip all values in current document
		__declspec(noinline) void drop()
		{
			while (begin < end && *begin != byte::terminator)
			{
				skip(0);
			}
		}

		// Write data (raw)
		void write(const void* data, std::size_t _size)
		{
			if (begin)
			{
				std::memcpy(begin, data, _size);
				begin += _size;
			}
			else
			{
				psize += _size;
			}
		}

		// Write data (raw)
		template <typename T>
		void operator+=(const T& rhs)
		{
			write(&rhs, sizeof(T));
		}

		// Write size (8, 32 or 64-bit)
		void operator+=(const size_type& rhs)
		{
			if (rhs.value < 256)
			{
				*this += static_cast<uchar>(rhs.value);
			}
			else if (rhs.value <= UINT32_MAX)
			{
				*this += static_cast<std::be_t<std::uint32_t, 1>>(static_cast<std::uint32_t>(rhs.value));
			}
			else
			{
				*this += static_cast<std::be_t<std::uint64_t, 1>>(rhs.value);
			}
		}

		// Write sized data
		void write_sized(const void* data, const size_type& _size)
		{
			if (_size.value == 0)
			{
				// Zero size optimization
				*this += byte::bit_false;
				return;
			}

			*this += _size.type_sized();
			*this += _size;

			if (begin)
			{
				std::memcpy(begin, data, _size.value);
				begin += _size.value;
			}
			else
			{
				psize += _size.value;
			}
		}

		template <context_type Type, typename T>
		void traverse(T& arg)
		{
			sstl::traverse<Type, T>::op(*this, arg);
		}

		template <context_type Type, typename T, typename F>
		void traverse_container(T& arg, F&& serialize)
		{
			if (Type != context_type::reading)
			{
				if (arg.empty())
				{
					// Empty container optimization
					*this += byte::bit_false;
				}
				else
				{
					*this += byte::document;
					serialize(*this);
					*this += byte::terminator;
				}

				return;
			}

			if (remaining() == 0)
			{
				return;
			}

			if (*begin == byte::document || *begin == byte::bit_false)
			{
				arg.clear();

				if (*begin++ == byte::document)
				{
					// Check recursion level
					if (++psize < max_level()) serialize(*this);
					skip(1);
					psize--;
				}

				return;
			}

			if (*begin == byte::null_value)
			{
				begin += 1;
				return;
			}

			drop();
		}

		template <context_type Type, typename T>
		void traverse_container_simple(T& arg)
		{
			if (Type != context_type::reading)
			{
				if (arg.empty())
				{
					// Empty container optimization
					*this += byte::bit_false;
				}
				else if (sizeof(typename T::value_type) == 1)
				{
					// Byte array optimization (std::string, etc)
					write_sized(&arg.front(), arg.size());
				}
				else
				{
					const size_type size = arg.size() * sizeof(T);
					*this += size.type_sized();
					*this += size;

					for (typename is_simple<typename T::value_type>::data_type value : arg)
					{
						*this += value;
					}
				}

				return;
			}

			if (remaining() == 0)
			{
				return;
			}

			if (*begin == byte::bit_false)
			{
				begin += 1;
				is_simple<T>::resize(arg, 0);
				return;
			}

			if (*begin == byte::u8_sized || *begin == byte::u32_sized || *begin == byte::u64_sized)
			{
				const std::size_t size = read_size(*begin++);
				is_simple<T>::resize(arg, size);

				if (sizeof(typename T::value_type) == 1)
				{
					std::memcpy(&arg.front(), begin, std::min<std::size_t>(arg.size(), size));
					begin += size;
				}
				else
				{
					const auto last = begin + sizeof(typename T::value_type) * size;

					for (auto& value : arg)
					{
						if (begin < last)
						{
							typename is_simple<typename T::value_type>::data_type data;
							read(&data, sizeof(typename T::value_type));
							value = data;
						}
					}

					begin = last;
				}

				return;
			}

			if (*begin == byte::null_value)
			{
				begin += 1;
				return;
			}

			drop();
		}
	};

	template <context_type Type>
	class context final
	{
		context_data* m_ctx;

	public:
		static constexpr context_type type = Type;

		context() = default;

		context(context_data& ref)
			: m_ctx(&ref)
		{
		}

		// Traverse one or more objects
		template <typename Arg, typename... Args>
		void operator()(Arg& arg, Args&... args) const
		{
			// Execute sequentially
			int dummy[]{(m_ctx->traverse<Type>(arg), 0), (m_ctx->traverse<Type>(args), 0)...};
		}

		// True if reading and not end of file/document
		explicit operator bool() const
		{
			return Type == context_type::reading && m_ctx->begin < m_ctx->end && *m_ctx->begin != byte::terminator;
		}

		// Traverse one or more null values (deleted or moved objects)
		void null(std::size_t count = 1) const
		{
			while (count--)
			{
				if (Type != context_type::reading)
				{
					*m_ctx += byte::null_value;
				}
				else
				{
					m_ctx->skip(0);
				}
			}
		}

		// Traverse fixed metadata string
		void name(const char* str) const
		{
			std::size_t len = 0;

			// Calculate CCTS size
			while (static_cast<byte>(str[len]) > byte::null_value)
			{
				len++;
			}

			if (Type != context_type::reading)
			{
				m_ctx->write(str, len);
				return;
			}

			// Check remaining size and compare metadata
			if (m_ctx->remaining() >= len && std::memcmp(m_ctx->begin, str, len) == 0)
			{
				m_ctx->begin += len;
				return;
			}

			m_ctx->drop();
		}

		// Traverse object via temporary variable of different type
		template <typename CustomType, typename Arg>
		void as(Arg& arg) const
		{
			if (Type != context_type::reading)
			{
				CustomType value = static_cast<CustomType>(arg);
				m_ctx->traverse<Type>(value);
			}
			else
			{
				CustomType temp{};
				m_ctx->traverse<Type>(temp);
				arg = std::move(temp);
			}
		}
	};

	template <context_type Type, typename T, typename>
	struct traverse
	{
		static void op(context_data& ctx, T& arg)
		{
			if (Type != context_type::reading)
			{
				ctx += byte::document;
				arg.serialize(context<Type>{ctx});
				ctx += byte::terminator;
				return;
			}

			if (ctx.remaining() == 0)
			{
				return;
			}

			if (*ctx.begin == byte::document)
			{
				ctx.begin += 1;

				// Check recursion level
				if (++ctx.psize < ctx.max_level()) arg.serialize(context<Type>{ctx});
				ctx.skip(1);
				ctx.psize--;
				return;
			}

			if (*ctx.begin == byte::null_value)
			{
				ctx.begin += 1;
				return;
			}

			ctx.drop();
		}
	};

	template <context_type Type, typename T>
	struct traverse<Type, T, typename is_simple<T>::simple>
	{
		static constexpr byte my_type =
			sizeof(T) == 1 ? byte::u8_value :
			sizeof(T) == 4 ? byte::u32_value :
			sizeof(T) == 8 ? byte::u64_value :
			sizeof(T) < 256 ? byte::u8_sized : byte::u32_sized;

		static void op(context_data& ctx, T& arg)
		{
			if (Type != context_type::reading)
			{
				if (arg == T{})
				{
					// Zero (default) value optimization
					ctx += byte::bit_false;
				}
				else if /*constexpr*/(my_type == byte::u8_sized || my_type == byte::u32_sized)
				{
					typename is_simple<T>::data_type data{arg};
					ctx.write_sized(&data, sizeof(T));
				}
				else
				{
					ctx += my_type;
					ctx += typename is_simple<T>::data_type{arg};
				}

				return;
			}

			if (ctx.begin < ctx.end)
			{
				if (*ctx.begin == byte::bit_false)
				{
					ctx.begin += 1;
					arg = T{};
				}
				else if (*ctx.begin == my_type)
				{
					ctx.begin += 1;

					if /*constexpr*/(my_type == byte::u8_sized || my_type == byte::u32_sized)
					{
						if (ctx.read_size(my_type) == sizeof(T))
						{
							typename is_simple<T>::data_type data;
							ctx.read(&data, sizeof(T));
							arg = data;
						}
						else
						{
							// Invalid size: abort document
							ctx.begin += sizeof(T);
							ctx.drop();
						}
					}
					else
					{
						typename is_simple<T>::data_type data;
						ctx.read(&data, sizeof(T));
						arg = data;
					}
				}
				else if (*ctx.begin == byte::null_value)
				{
					ctx.begin += 1;
				}
				else
				{
					ctx.drop();
				}
			}
		}
	};

	template <context_type Type>
	struct traverse<Type, bool>
	{
		static void op(context_data& ctx, bool& arg)
		{
			if (Type != context_type::reading)
			{
				ctx += arg ? byte::bit_true : byte::bit_false;
				return;
			}

			if (ctx.remaining() == 0)
			{
				return;
			}

			if (*ctx.begin == byte::bit_false || *ctx.begin == byte::bit_true)
			{
				arg = *ctx.begin++ == byte::bit_true;
				return;
			}

			if (*ctx.begin == byte::null_value)
			{
				ctx.begin += 1;
				return;
			}

			ctx.drop();
		}
	};

	template <context_type Type>
	struct traverse<Type, size_type>
	{
		static void op(context_data& ctx, size_type& arg)
		{
			if (Type != context_type::reading)
			{
				if (arg.value == 0)
				{
					// Zero size optimization
					ctx += byte::bit_false;
				}
				else
				{
					ctx += arg.type_value();
					ctx += arg;
				}

				return;
			}

			if (ctx.remaining() == 0)
			{
				return;
			}

			if (*ctx.begin == byte::bit_false)
			{
				ctx.begin += 1;
				arg = 0;
				return;
			}

			if (*ctx.begin == byte::u8_value || *ctx.begin == byte::u32_value || *ctx.begin == byte::u64_value)
			{
				arg = ctx.read_size(*ctx.begin++);
				return;
			}

			if (*ctx.begin == byte::null_value)
			{
				ctx.begin += 1;
				return;
			}

			ctx.drop();
		}
	};

	template <context_type Type, typename CT>
	struct traverse<Type, CT, typename is_simple<CT>::simple_container>
	{
		static void op(context_data& ctx, CT& arg)
		{
			ctx.traverse_container_simple<Type>(arg);
		}
	};

	template <context_type Type, std::size_t N>
	struct traverse<Type, std::bitset<N>, void>
	{
		static_assert(!N, "std::bitset<> support is incomplete");

		static void op(context_data& ctx, std::bitset<N>& arg)
		{
			if (Type != context_type::reading)
			{
				size_type size = 0;

				// Get buffer size with empty tail optimization
				for (std::size_t i = arg.none() ? N : 0; i < N; i++)
				{
					if (arg[i]) size.value = i / 8 + 1;
				}

				if (size.value == 0)
				{
					ctx += byte::bit_false;
				}
				else
				{
					ctx += size.type_sized();
					ctx += size;

					if (ctx.begin)
					{
						std::memset(ctx.begin, 0, size);

						for (std::size_t i = 0; i < N; i++)
						{
							if (arg[i]) ctx.begin[i / 8] |= 1 << (i % 8);
						}

						ctx.begin += size.value;
					}
					else
					{
						ctx.psize += size.value;
					}
				}

				return;
			}

			if (ctx.remaining() == 0)
			{
				return;
			}

			if (*ctx.begin == byte::bit_false)
			{
				ctx.begin += 1;
				arg.reset();
				return;
			}

			if (*ctx.begin == byte::u8_sized || *ctx.begin == byte::u32_sized || *ctx.begin == byte::u64_sized)
			{
				const std::size_t size = ctx.read_size(*ctx.begin++);

				for (std::size_t i = 0, m = std::min<std::size_t>(N, 8 * size); i < m; i++)
				{
					arg.set(i, ctx.begin[i / 8] & (1 << (i % 8)) != 0);
				}

				ctx.begin += size;
				return;
			}

			if (*ctx.begin == byte::null_value)
			{
				ctx.begin += 1;
				return;
			}

			ctx.drop();
		}
	};

	template <context_type Type, typename T, typename D>
	struct traverse<Type, std::unique_ptr<T, D>, void>
	{
		static void op(context_data& ctx, std::unique_ptr<T, D>&)
		{
			if (Type != context_type::reading)
			{
				ctx += byte::null_value;
				return;
			}

			ctx.skip(0);
		}
	};

	template <context_type Type, typename T>
	struct traverse<Type, std::shared_ptr<T>, void>
	{
		static void op(context_data& ctx, std::shared_ptr<T>&)
		{
			if (Type != context_type::reading)
			{
				ctx += byte::null_value;
				return;
			}

			ctx.skip(0);
		}
	};

	template <context_type Type, typename T, std::size_t N>
	struct traverse<Type, std::array<T, N>, typename is_simple<T>::complex>
	{
		static void op(context_data& ctx, std::array<T, N>& arg)
		{
			ctx.traverse_container<Type>(arg, [&](context<Type> ctx)
			{
				for (auto&& val : arg)
				{
					ctx(val);
				}
			});
		}
	};

	template <context_type Type, typename T, typename A>
	struct traverse<Type, std::vector<T, A>, typename is_simple<T>::complex>
	{
		static void op(context_data& ctx, std::vector<T, A>& arg)
		{
			ctx.traverse_container<Type>(arg, [&](context<Type> ctx)
			{
				size_type size = arg.size();
				ctx(size);
				arg.reserve(size.value);

				for (auto&& val : arg)
				{
					ctx(val);
				}

				while (ctx)
				{
					arg.emplace_back();
					ctx(arg.back());
				}
			});
		}
	};

	template <context_type Type, typename T, typename R, typename A>
	struct traverse<Type, std::basic_string<T, R, A>, typename is_simple<T>::complex>
	{
		static void op(context_data& ctx, std::basic_string<T, R, A>& arg)
		{
			ctx.traverse_container<Type>(arg, [&](context<Type> ctx)
			{
				size_type size = arg.size();
				ctx(size);
				arg.reserve(size.value);

				for (auto&& val : arg)
				{
					ctx(val);
				}

				while (ctx)
				{
					arg.emplace_back();
					ctx(arg.back());
				}
			});
		}
	};

	template <context_type Type, typename T, typename A>
	struct traverse<Type, std::deque<T, A>, void>
	{
		static void op(context_data& ctx, std::deque<T, A>& arg)
		{
			ctx.traverse_container<Type>(arg, [&](context<Type> ctx)
			{
				for (auto&& val : arg)
				{
					ctx(val);
				}

				while (ctx)
				{
					arg.emplace_back();
					ctx(arg.back());
				}
			});
		}
	};

	template <context_type Type, typename K, typename L, typename A>
	struct traverse<Type, std::set<K, L, A>>
	{
		static void op(context_data& ctx, std::set<K, L, A>& set)
		{
			ctx.traverse_container<Type>(set, [&](context<Type> ctx)
			{
				size_type size = set.size();
				ctx(size);

				for (auto& key : set)
				{
					ctx(const_cast<K&>(key));
				}

				while (ctx)
				{
					K key{};
					ctx(key);
					set.emplace_hint(set.cend(), std::move(key));
				}
			});
		};
	};

	template <context_type Type, typename K, typename L, typename A>
	struct traverse<Type, std::multiset<K, L, A>>
	{
		static void op(context_data& ctx, std::multiset<K, L, A>& set)
		{
			ctx.traverse_container<Type>(set, [&](context<Type> ctx)
			{
				size_type size = set.size();
				ctx(size);

				for (auto& key : set)
				{
					ctx(const_cast<K&>(key));
				}

				while (ctx)
				{
					K key{};
					ctx(key);
					set.emplace_hint(set.cend(), std::move(key));
				}
			});
		};
	};

	template <context_type Type, typename K, typename H, typename E, typename A>
	struct traverse<Type, std::unordered_set<K, H, E, A>>
	{
		static void op(context_data& ctx, std::unordered_set<K, H, E, A>& set)
		{
			ctx.traverse_container<Type>(set, [&](context<Type> ctx)
			{
				size_type size = set.size();
				ctx(size);
				set.reserve(size.value);

				for (auto& key : set)
				{
					ctx(const_cast<K&>(key));
				}

				while (ctx)
				{
					K key{};
					ctx(key);
					set.emplace(std::move(key));
				}
			});
		};
	};

	template <context_type Type, typename K, typename H, typename E, typename A>
	struct traverse<Type, std::unordered_multiset<K, H, E, A>>
	{
		static void op(context_data& ctx, std::unordered_multiset<K, H, E, A>& set)
		{
			ctx.traverse_container<Type>(set, [&](context<Type> ctx)
			{
				size_type size = set.size();
				ctx(size);
				set.reserve(size.value);

				for (auto& key : set)
				{
					ctx(const_cast<K&>(key));
				}

				while (ctx)
				{
					K key{};
					ctx(key);
					set.emplace(std::move(key));
				}
			});
		};
	};

	template <context_type Type, typename K, typename T, typename L, typename A>
	struct traverse<Type, std::map<K, T, L, A>>
	{
		static void op(context_data& ctx, std::map<K, T, L, A>& map)
		{
			ctx.traverse_container<Type>(map, [&](context<Type> ctx)
			{
				size_type size = map.size();
				ctx(size);

				for (auto& val : map)
				{
					ctx(const_cast<K&>(val.first));
					ctx(val.second);
				}

				while (ctx)
				{
					K key{};
					ctx(key);
					ctx(map.emplace_hint(map.cend(), std::piecewise_construct, std::forward_as_tuple(std::move(key)), std::forward_as_tuple()).first->second);
				}
			});
		};
	};

	template <context_type Type, typename K, typename T, typename L, typename A>
	struct traverse<Type, std::multimap<K, T, L, A>>
	{
		static void op(context_data& ctx, std::multimap<K, T, L, A>& map)
		{
			ctx.traverse_container<Type>(map, [&](context<Type> ctx)
			{
				size_type size = map.size();
				ctx(size);

				for (auto& val : map)
				{
					ctx(const_cast<K&>(val.first));
					ctx(val.second);
				}

				while (ctx)
				{
					K key{};
					ctx(key);
					ctx(map.emplace_hint(map.cend(), std::piecewise_construct, std::forward_as_tuple(std::move(key)), std::forward_as_tuple())->second);
				}
			});
		};
	};

	template <context_type Type, typename K, typename T, typename H, typename E, typename A>
	struct traverse<Type, std::unordered_map<K, T, H, E, A>>
	{
		static void op(context_data& ctx, std::unordered_map<K, T, H, E, A>& map)
		{
			ctx.traverse_container<Type>(map, [&](context<Type> ctx)
			{
				size_type size = map.size();
				ctx(size);
				map.reserve(size.value);

				for (auto& val : map)
				{
					ctx(const_cast<K&>(val.first));
					ctx(val.second);
				}

				while (ctx)
				{
					K key{};
					ctx(key);
					ctx(map.emplace(std::piecewise_construct, std::forward_as_tuple(std::move(key)), std::forward_as_tuple()).first->second);
				}
			});
		};
	};

	template <context_type Type, typename K, typename T, typename H, typename E, typename A>
	struct traverse<Type, std::unordered_multimap<K, T, H, E, A>>
	{
		static void op(context_data& ctx, std::unordered_multimap<K, T, H, E, A>& map)
		{
			ctx.traverse_container<Type>(map, [&](context<Type> ctx)
			{
				size_type size = map.size();
				ctx(size);
				map.reserve(size.value);

				for (auto& val : map)
				{
					ctx(const_cast<K&>(val.first));
					ctx(val.second);
				}

				while (ctx)
				{
					K key{};
					ctx(key);
					ctx(map.emplace(std::piecewise_construct, std::forward_as_tuple(std::move(key)), std::forward_as_tuple())->second);
				}
			});
		};
	};

	// Load from raw buffer
	template <typename F>
	std::size_t load(const void* data, std::size_t size, F&& serialize)
	{
		// Deserialize (const_cast is required; no write access will happen)
		context_data ctx(context_type::reading, static_cast<byte*>(const_cast<void*>(data)), size);
		serialize(context<context_type::reading>{ctx});

		return ctx.begin - data;
	}

	template <typename T, typename F>
	std::size_t load(const T& data, F&& serialize)
	{
		static_assert(sizeof(*data.data()) == 1, "Unexpected input data element type");

		return load(data.data(), data.size(), std::forward<F>(serialize));
	}

	// Append to buffer
	template <typename T, typename F>
	std::size_t append(T& out, F&& serialize)
	{
		static_assert(sizeof(out.front()) == 1, "Unexpected output buffer element type");

		// Calculate size for vector
		context_data probe(context_type::probing);
		serialize(context<context_type::probing>{probe});

		// Serialize
		if (const auto psize = probe.psize)
		{
			const auto pos = out.size();
			out.resize(out.size() + psize);
			context_data ctx(context_type::writing, reinterpret_cast<byte*>(&out.front() + pos), psize);
			serialize(context<context_type::writing>{ctx});

			return psize;
		}

		return 0;
	}

	// Save buffer
	template <typename T = std::vector<uchar>, typename F>
	T save(F&& serialize)
	{
		T result;
		append(result, std::forward<F>(serialize));
		return result;
	}
}
