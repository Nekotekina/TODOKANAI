#pragma once

#include <string>
#include "util/sfs.hpp"

extern "C"
{
	typedef struct hmac_ctx_st HMAC_CTX;
}

using uchar = unsigned char;

namespace to
{
	class master_key final
	{
		// HMAC context (SHA-512)
		HMAC_CTX* m_hmac;

		// Path to the key file
		std::string m_key_path;

		// Key file kept opened
#ifdef _WIN32
		void* m_key_file;
#else
		int m_key_file;
#endif

		// Password pointer
		char* m_pass{};

		std::size_t m_pass_size{};

		// Last derived key
		uchar m_result[64]{};

		// Key generated from the password (key file contents)
		uchar m_secret[128]{};

	public:
		// Total number of dictionaries
		static std::size_t dict_count();

		// Dictionary name for GUI
		static std::string dict_name(std::size_t dict_id);

		// Compute bit strength of a single element (x100, rounded towards zero)
		static int dict_strength(std::size_t dict_id);

		master_key(const uchar* secret, std::size_t size);

		master_key(const std::string& key_path);

		master_key(const master_key&) = delete;

		~master_key();

		void reset();

		void init(const uchar* secret, std::size_t size);

		void init(const char* pass, std::size_t len);

		const uchar* get(const char* info, std::size_t info_size = -1);

		void generate(const std::string& prefix, std::size_t dict_id, int len);

		bool load();

		void save();

		void set_pass(const char* pass, std::size_t len);

		bool gui_ask(const char* prefix = "");

		bool gui_gen();

		const char* get_pass() const
		{
			return m_pass;
		}

		std::size_t get_pass_size() const
		{
			return m_pass_size;
		}
	};
}
