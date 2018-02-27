#pragma once

#include <atomic>
#include <memory>
#include <utility>
#include <cstdint>

namespace lfs
{
	template <typename T>
	class list_item final
	{
		list_item* m_link{};

		T m_data;

		template <typename TT>
		friend class list;

	public:
		constexpr list_item() = default;

		template <typename... Args>
		constexpr list_item(list_item* link, Args&&... args)
			: m_link{link}
			, m_data(std::forward<Args>(args)...)
		{
		}

		// Delete copy/move constructors and operators
		list_item(const list_item&) = delete;

		~list_item()
		{
			for (list_item* ptr = m_link; ptr;)
			{
				delete std::exchange(ptr, std::exchange(ptr->m_link, nullptr));
			}
		}

		std::unique_ptr<list_item<T>> pop_all()
		{
			return std::unique_ptr<list_item<T>>(std::exchange(m_link, nullptr));
		}

		T& get()
		{
			return m_data;
		}

		const T& get() const
		{
			return m_data;
		}
	};

	template <typename T>
	class list
	{
		// Elements are added by replacing m_head
		std::atomic<list_item<T>*> m_head{};

	public:
		constexpr list() = default;

		~list()
		{
			delete m_head.load(std::memory_order_relaxed);
		}

		template <typename... Args>
		void push(Args&&... args)
		{
			list_item<T>* old = m_head.load();
			list_item<T>* item = new list_item<T>(old, std::forward<Args>(args)...);
			while (!m_head.compare_exchange_strong(old, item))
			{
				item->m_link = old;
			}
		}

		// Withdraw the list
		std::unique_ptr<list_item<T>> pop_all()
		{
			return std::unique_ptr<list_item<T>>(m_head.exchange(nullptr));
		}

		// Withdraw the list and apply func(data) to each element in FIFO order
		template <typename F>
		std::size_t apply(F&& func)
		{
			std::size_t count{0};

			if (list_item<T>* head = m_head.load() ? m_head.exchange(nullptr) : nullptr)
			{
				// Reverse element order in linked list
				if (list_item<T>* prev = head->m_link)
				{
					head->m_link = nullptr;

					do
					{
						list_item<T>* pprev = prev->m_link;
						prev->m_link = head;
						head = std::exchange(prev, pprev);
					}
					while (prev);
				}

				for (std::unique_ptr<list_item<T>> ptr(head); ptr; ptr = ptr->pop_all(), count++)
				{
					func(ptr->m_data);
				}
			}

			return count;
		}
	};
}
