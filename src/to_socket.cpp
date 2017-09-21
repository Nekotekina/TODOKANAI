#define NOMINMAX
#include <ctime>
#include <vector>
#include <algorithm>
#include "to_socket.hpp"

#ifdef _WIN32
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <Windows.h>
#else
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#endif

#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif

namespace
{
	// setsockopt arg wrapper
	template <typename T>
	struct sock_opt
	{
		T value;

		operator char*()
		{
			return reinterpret_cast<char*>(&value);
		}

		operator T*()
		{
			return &value;
		}
	};
}

#ifdef _WIN32
static inline int make_socket(std::uintptr_t s)
{
	if (s < 0 || s > INT_MAX)
	{
		if (s != INVALID_SOCKET)
		{
			::closesocket(s);
		}

		return -1;
	}

	// Narrow for OpenSSL
	return static_cast<int>(s);
}

static inline int close_socket(int s)
{
	return ::closesocket(s);
}

static inline void set_nonblocking(int s)
{
	::ioctlsocket(s, FIONBIO, sock_opt<u_long>{1});
}

static inline bool has_blocked()
{
	return WSAGetLastError() == WSAEWOULDBLOCK;
}

static constexpr auto poll = WSAPoll;
#else
static inline int make_socket(int s)
{
	return s;
}

static inline int close_socket(int s)
{
	return ::close(s);
}

static inline void set_nonblocking(int s)
{
	::fcntl(s, F_SETFL, ::fcntl(s, F_GETFL, 0) | O_NONBLOCK);
}

static inline bool has_blocked()
{
	return errno == EWOULDBLOCK || errno == EAGAIN;
}
#endif

int to::send(int s, const void* ptr, std::size_t size)
{
	int r = std::max(-1, ::send(s, static_cast<const char*>(ptr), size > INT_MAX ? INT_MAX : static_cast<int>(size), 0));

	if (r == -1 && has_blocked())
	{
		return 0;
	}

	if (r == 0 && size > 0)
	{
		return -2;
	}

	return r;
}

int to::recv(int s, void* ptr, std::size_t size)
{
	int r = std::max(-1, ::recv(s, static_cast<char*>(ptr), size > INT_MAX ? INT_MAX : static_cast<int>(size), 0));

	if (r == -1 && has_blocked())
	{
		return 0;
	}

	if (r == 0 && size > 0)
	{
		return -2;
	}

	return r;
}

int to::peek(int s, void* ptr, std::size_t size)
{
	int r = std::max(-1, ::recv(s, static_cast<char*>(ptr), size > INT_MAX ? INT_MAX : static_cast<int>(size), MSG_PEEK));

	if (r == -1 && has_blocked())
	{
		return 0;
	}

	if (r == 0 && size > 0)
	{
		return -2;
	}

	return r;
}

to::server_thread::server_thread()
{
#ifdef _WIN32
	::WSADATA wsaData;
	::WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
}

to::server_thread::~server_thread()
{
	terminate();

#ifdef _WIN32
	::WSACleanup();
#endif
}

void to::server_thread::start(const char* bind_addr, const char* bind_port, const accept_func& on_accept)
{
	terminate();

	// Get addr info
	struct ::addrinfo hints{};
	struct ::addrinfo* info;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;

	if (::getaddrinfo(bind_addr, bind_port, &hints, &info) == 0)
	{
		// Create listener socket
		int listener = make_socket(::socket(info->ai_family, info->ai_socktype, info->ai_protocol));

		if (listener != -1)
		{
			::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, sock_opt<int>{1}, sizeof(int));
			::setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, sock_opt<int>{0}, sizeof(int));
			set_nonblocking(listener);

			if (::bind(listener, info->ai_addr, static_cast<int>(info->ai_addrlen)) == 0)
			{
				if (::listen(listener, SOMAXCONN) == 0)
				{
					m_state  = thread_state::running;
					m_thread = std::thread([=]()
					{
						std::vector<::pollfd> fds;
						fds.emplace_back();
						fds[0].fd      = listener;
						fds[0].events  = POLLIN;
						fds[0].revents = 0;

						// Loop with 20 ms timeout and simple termination condition check
						while (::poll(fds.data(), static_cast<u_long>(fds.size()), 20) >= 0 && !(fds[0].revents & ~POLLIN) && m_state != thread_state::terminated)
						{
							while (fds[0].revents & POLLIN)
							{
								int socket = make_socket(::accept(listener, 0, 0));

								if (socket == -1)
								{
									fds[0].revents = 0;
									break;
								}

								// Upon accepting, add socket to the polling queue
								fds.emplace_back();
								fds.back().fd      = socket;
								fds.back().events  = POLLIN;
								fds.back().revents = 0;
							}

							std::size_t nullstat = 0;
							std::size_t allstat = fds.size() - 1;

							for (auto& pfd : fds)
							{
								if (pfd.fd == -1)
								{
									nullstat++;
								}

								// Upon the first data available, try to read from socket and verify
								if (pfd.fd != -1 && pfd.revents)
								{
									nullstat++;

									// Get socket handle, reset poll location
									const int socket = make_socket(std::exchange(pfd.fd, -1));

									// Check for possible errors
									if (socket == -1 || pfd.revents & ~POLLIN)
									{
										::close_socket(socket);
										continue;
									}

									// Preliminary verification
									if (!on_accept(socket, nullptr, nullptr) && allstat - nullstat > 3)
									{
										::close_socket(socket);
										continue;
									}

									set_nonblocking(socket);
									::setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, sock_opt<int>{1}, sizeof(int));

									// Get socket name
									::sockaddr_storage addr;
									int sock_len = sizeof(addr);
									char hbuf[NI_MAXHOST];
									char sbuf[NI_MAXSERV];
									::getsockname(socket, (struct ::sockaddr*)&addr, &sock_len);
									::getnameinfo((struct ::sockaddr*)&addr, sock_len, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV);

									// Now should finally create a socket thread
									if (!on_accept(socket, hbuf, sbuf))
									{
										::close_socket(socket);
									}
								}
							}

							if (nullstat >= allstat)
							{
								// Clean all (simple)
								fds.resize(1);
							}
							else if (nullstat > allstat - allstat / 10)
							{
								// Clean all (hard way)
								fds.erase(std::remove_if(fds.begin() + 1, fds.end(), [](auto& pfd) { return pfd.fd == -1; }), fds.end());
							}
							else if (nullstat > 10)
							{
								// Clean back (it's a dirty draft anyway)
								for (std::size_t i = fds.size() - 1; ~i; i--)
								{
									if (fds[i].fd != -1)
									{
										fds.resize(i + 1);
										break;
									}
								}
							}
						}

						::close_socket(listener);
						::freeaddrinfo(info);
						m_state = thread_state::terminated;
					});

					return;
				}
			}

			::close_socket(listener);
		}

		::freeaddrinfo(info);
	}
}

void to::server_thread::terminate()
{
	if (m_thread.joinable())
	{
		m_state = thread_state::terminated;
		m_thread.join();
		m_state = thread_state::null;
	}
}

to::socket_thread::socket_thread()
{
	// Create polling handles
#ifdef _WIN32
	::WSADATA wsaData;
	::WSAStartup(MAKEWORD(2, 2), &wsaData);

	// Create autoreset event
	m_event = ::CreateEventW(nullptr, false, false, nullptr);
#else
	::pipe(m_pipe);
	::fcntl(m_pipe[0], F_SETFL, ::fcntl(m_pipe[0], F_GETFL, 0) | O_NONBLOCK);
	::fcntl(m_pipe[1], F_SETFL, ::fcntl(m_pipe[1], F_GETFL, 0) | O_NONBLOCK);
#endif
}

to::socket_thread::~socket_thread()
{
	terminate();

#ifdef _WIN32
	::WSACloseEvent(m_event);
	::WSACleanup();
#else
	for (auto pipe : m_pipe)
	{
		::close(pipe);
	}
#endif
}

bool to::socket_thread::task(int s, cb_arg& arg, const std::function<cb_res(cb_arg&)>& on_check)
{
#ifdef _WIN32
	// Initial event list (TODO)
	long last_events = m_is_client ? FD_CLOSE | FD_CONNECT : FD_CLOSE | FD_READ;

	::WSAEventSelect(s, m_event, last_events);

	while (true)
	{
		::DWORD result = ::WaitForSingleObjectEx(m_event, m_timeout, false);

		// Check network events
		::WSANETWORKEVENTS nwev{};

		if ((result != WSA_WAIT_EVENT_0 && result != WSA_WAIT_TIMEOUT) ||
			m_state == thread_state::terminated ||
			::WSAEnumNetworkEvents(s, m_event, &nwev) != 0 ||
			nwev.lNetworkEvents & FD_CLOSE ||
			nwev.lNetworkEvents & FD_READ && nwev.iErrorCode[FD_READ_BIT] ||
			nwev.lNetworkEvents & FD_WRITE && nwev.iErrorCode[FD_WRITE_BIT])
		{
			return (last_events & FD_CONNECT) != 0;
		}

		if (nwev.lNetworkEvents & FD_CONNECT)
		{
			if (nwev.iErrorCode[FD_CONNECT_BIT])
			{
				return false;
			}

			m_socket = s;
			m_time = std::time(nullptr);
			last_events = FD_CLOSE | FD_READ;
			::WSAEventSelect(s, m_event, last_events);
		}

		if (result == WSA_WAIT_TIMEOUT)
		{
			arg = cb_arg::signal_timeout;
		}
		else if (nwev.lNetworkEvents & FD_READ && nwev.lNetworkEvents & FD_WRITE)
		{
			arg = cb_arg::signal_both;
		}
		else if (nwev.lNetworkEvents & FD_WRITE)
		{
			arg = cb_arg::signal_write;
		}
		else if (nwev.lNetworkEvents & FD_READ)
		{
			arg = cb_arg::signal_read;
		}
		else
		{
			arg = cb_arg::signal_none;
		}

		// Don't call the callback until the connection succeeds
		while ((last_events & FD_CONNECT) == 0)
		{
			long new_events = last_events;

			// Process callback result
			switch (on_check(arg))
			{
			case cb_res::terminate: return true;
			case cb_res::wait_none: new_events = FD_CLOSE; break;
			case cb_res::wait_read: new_events = FD_CLOSE | FD_READ; break;
			case cb_res::wait_both: new_events = FD_CLOSE | FD_READ | FD_WRITE; break;
			case cb_res::wait_write: new_events = FD_CLOSE | FD_WRITE; break;
			case cb_res::retry: continue;
			}

			if (last_events != new_events)
			{
				// Update event list when necessary
				::WSAEventSelect(s, m_event, new_events);
				last_events = new_events;
			}

			break;
		}
	}
#else
	::pollfd fds[2]{};
	fds[0].fd     = s;
	fds[0].events = POLLIN | POLLOUT;
	fds[1].fd     = m_pipe[0];
	fds[1].events = POLLIN;
	bool is_connected = !m_is_client;

	while (::poll(fds, 2, m_timeout) != -1 && !(fds[0].revents & ~(POLLIN | POLLOUT)) && !(fds[1].revents & ~POLLIN) && m_state != thread_state::terminated)
	{
		// Read signal
		while (fds[1].revents)
		{
			char cmd;
			if (::read(m_pipe[0], &cmd, 1) < 1)
			{
				break;
			}
		}

		// Check connection result
		if (fds[0].revents && !is_connected)
		{
			sock_opt<int> err{-1};
			::getsockopt(s, SOL_SOCKET, SO_ERROR, err, sizeof(int));

			if (err.value != 0)
			{
				return false;
			}

			m_socket = s;
			m_time = std::time(nullptr);
			is_connected = true;
			fds[0].revents &= ~POLLOUT;
		}

		if (fds[0].revents & POLLIN && fds[0].revents & POLLOUT)
		{
			arg = cb_arg::signal_both;
		}
		else if (fds[0].revents & POLLOUT)
		{
			arg = cb_arg::signal_write;
		}
		else if (fds[0].revents & POLLIN)
		{
			arg = cb_arg::signal_read;
		}
		else if (fds[1].revents & POLLIN)
		{
			arg = cb_arg::signal_none;
		}
		else
		{
			arg = cb_arg::signal_timeout;
		}

		// Don't call the callback until the connection succeeds
		while (is_connected)
		{
			// Process callback result
			switch (on_check(arg))
			{
			case cb_res::terminate: return true;
			case cb_res::wait_none: fds[0].events = 0; break;
			case cb_res::wait_read: fds[0].events = POLLIN; break;
			case cb_res::wait_both: fds[0].events = POLLIN | POLLOUT; break;
			case cb_res::wait_write: fds[0].events = POLLOUT; break;
			case cb_res::retry: continue;
			}

			break;
		}
	}

	return is_connected;
#endif
}

void to::socket_thread::start(const char* target, const char* port, const std::function<cb_res(cb_arg&)>& on_check)
{
	terminate();
	m_addr.assign(target);
	m_port.assign(port);
	m_is_client = true;
	m_time = 0;

	m_state  = thread_state::running;
	m_thread = std::thread([=]
	{
		cb_arg arg = cb_arg::signal_none;

		while (m_state != thread_state::terminated)
		{
			// Get addr info
			struct ::addrinfo hints{};
			struct ::addrinfo* info;
			hints.ai_flags = AI_PASSIVE;
			hints.ai_socktype = SOCK_STREAM;

			if (int err = ::getaddrinfo(target, port, &hints, &info))
			{
				if (err == EAI_AGAIN)
				{
					continue;
				}

				// TODO
				m_state = thread_state::terminated;
				return;
			}

			// Reconnection loop
			while (m_state != thread_state::terminated)
			{
				int connection = make_socket(::socket(info->ai_family, info->ai_socktype, info->ai_protocol));

				if (connection == -1)
				{
					m_state = thread_state::terminated;
					break;
				}

				set_nonblocking(connection);
				::setsockopt(connection, IPPROTO_TCP, TCP_NODELAY, sock_opt<int>{1}, sizeof(int));

				// Initiate connection
				if (::connect(connection, info->ai_addr, static_cast<int>(info->ai_addrlen)) != 0)
				{
#ifdef _WIN32
					if (WSAGetLastError() != WSAEWOULDBLOCK)
#else
					if (errno != EINPROGRESS && errno != EAGAIN)
#endif
					{
						m_state = thread_state::terminated;
						::close_socket(connection);
						break;
					}
				}

				// Enter main loop
				if (!task(connection, arg, on_check))
				{
					::close_socket(connection);
					break;
				}

				arg = cb_arg::terminate;
				on_check(arg);
				::close_socket(connection);
			}

			::freeaddrinfo(info);
		}
	});
}

void to::socket_thread::start(int s, std::uint64_t time, const char* source, const char* port, const std::function<cb_res(cb_arg&)>& on_check)
{
	terminate();
	m_addr.assign(source);
	m_port.assign(port);
	m_is_client = false;
	m_time = time;
	m_socket = s;

	m_state  = thread_state::running;
	m_thread = std::thread([=]()
	{
		cb_arg arg = cb_arg::signal_none;
		task(m_socket, arg, on_check);
		arg = cb_arg::terminate;
		on_check(arg);
		::close_socket(m_socket);
		m_state = thread_state::terminated;
	});
}

void to::socket_thread::terminate()
{
	if (m_thread.joinable())
	{
		m_state = thread_state::terminated;

#ifdef _WIN32
		::WSASetEvent(m_event);
#else
		::write(m_pipe[1], "\0", 1);
#endif

		m_thread.join();

#ifdef _WIN32
		::WSAResetEvent(m_event);
#else
		char cmd;
		while (::read(m_pipe[0], &cmd, 1) == 1)
		{
		}
#endif

		m_time = 0;
		m_socket = -1;
		m_timeout = -1;
		m_state = thread_state::null;
	}
}

void to::socket_thread::signal()
{
#ifdef _WIN32
	::WSASetEvent(m_event);
#else
	::write(m_pipe[1], "\1", 1);
#endif
}
