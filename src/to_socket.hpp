#pragma once

#include <array>
#include <string>
#include <thread>
#include <atomic>
#include <functional>

using uchar = unsigned char;

namespace to
{
	// Socket send wrapper
	int send(int s, const void* ptr, std::size_t size);

	// Socket recv wrapper
	int recv(int s, void* ptr, std::size_t size);

	// Socket peek wrapper
	int peek(int s, void* ptr, std::size_t size);

	// Thread state
	enum class thread_state
	{
		null = 0,
		running,
		terminated,
	};

	using accept_func = std::function<bool(int s, const char* addr, const char* port)>;

	// TCP server thread class
	class server_thread final
	{
		// Server thread handle
		std::thread m_thread;

		// Server thread state
		std::atomic<thread_state> m_state{};

	public:
		server_thread();

		server_thread(const server_thread&) = delete;

		~server_thread();

		void start(const char* bind_addr, const char* bind_port, const accept_func& on_accept);

		void terminate();

		explicit operator bool() const
		{
			return m_thread.joinable();
		}
	};

	// Callback result: event loop control
	enum class cb_res
	{
		terminate,
		wait_none,
		wait_read,
		wait_write,
		wait_both,
		retry,
	};

	enum class cb_arg
	{
		terminate,
		signal_timeout,
		signal_none,
		signal_read,
		signal_write,
		signal_both,
	};

	// TCP connection thread class
	class socket_thread final
	{
		// Connection thread handle
		std::thread m_thread;

		std::string m_addr;
		std::string m_port;

		// Connection time
		std::uint64_t m_time = 0;

		int m_socket = -1;
		int m_timeout = -1;

#ifdef _WIN32
		// Autoreset Win32 event (socket events + ITC)
		void* m_event;
#else
		// Pipe for ITC
		int m_pipe[2];
#endif

		bool m_is_client;

		std::atomic<thread_state> m_state;

		// Internal thread task processing (returns false if connection failed or thread terminated)
		bool task(int s, cb_arg& arg, const std::function<cb_res(cb_arg&)>& on_check);

	public:
		socket_thread();

		socket_thread(const socket_thread&) = delete;

		explicit operator bool() const
		{
			return m_thread.joinable();
		}

		~socket_thread();

		// Initiate connection (client socket)
		void start(const char* target, const char* port, const std::function<cb_res(cb_arg&)>& on_check);

		// Proceed accepted connection (server)
		void start(int s, std::uint64_t time, const char* source, const char* port, const std::function<cb_res(cb_arg&)>& on_check);

		// Ask the thread to terminate.
		void terminate();

		// Wake up thread. Thread-safe.
		void signal();

		// Get socket
		int get() const
		{
			return m_socket;
		}

		// Get connection time
		std::uint64_t get_time() const
		{
			return m_time;
		}

		// Set socket
		void set(int s)
		{
			m_socket = s;
		}

		// Check socket type
		bool is_server() const
		{
			return !m_is_client;
		}

		bool is_client() const
		{
			return m_is_client;
		}

		bool is_current() const
		{
			return std::this_thread::get_id() == m_thread.get_id();
		}

		void set_timeout(int ms)
		{
			m_timeout = ms < 0 ? -1 : ms;
		}
	};
}
