/*
*
*    Copyright (C) Max <max1976@mail.ru>
*
*    This program is free software: you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation, either version 3 of the License, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*/

#ifndef __NFQTHREAD_H
#define __NFQTHREAD_H

#include <Poco/Task.h>
#include <Poco/Logger.h>
#include <Poco/NotificationQueue.h>

#define T_DATA_SIZE 4096

#define NFQ_BURST_FACTOR 4

class PktAnalyzer;

enum ADD_P_TYPES { A_TYPE_NONE, A_TYPE_ID, A_TYPE_URL };

struct nfqConfig
{
	int queueNumber;
	int max_pending_packets;
	int mark_value;
	bool send_rst;
	bool save_exception_dump;
	bool block_undetected_ssl;
	bool lower_host;
	bool match_host_exactly;
	bool url_decode;
	int num_threads;
	enum ADD_P_TYPES add_p_type;
};

struct threadStats
{
	uint64_t marked_ssl;
	uint64_t redirected_domains;
	uint64_t redirected_urls;
	uint64_t marked_hosts;
	uint64_t sended_rst;
	uint64_t ip_packets;
	uint64_t total_bytes;
	uint64_t matched_ssl;
	uint64_t matched_ssl_ip;
	uint64_t matched_ip_port;
};

class nfqThread: public Poco::Task
{
public:
	nfqThread(struct nfqConfig& cfg);
	virtual void runTask();
	static int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
	void getStats(threadStats &);

	void inc_marked_ssl()
	{
		Poco::Mutex::ScopedLock lock(_statsMutex);
		_stats.marked_ssl++;
	}

	void inc_redirected_domains()
	{
		Poco::Mutex::ScopedLock lock(_statsMutex);
		_stats.redirected_domains++;
	}

	void inc_redirected_urls()
	{
		Poco::Mutex::ScopedLock lock(_statsMutex);
		_stats.redirected_urls++;
	}

	void inc_marked_hosts()
	{
		Poco::Mutex::ScopedLock lock(_statsMutex);
		_stats.marked_hosts++;
	}

	void inc_sended_rst()
	{
		Poco::Mutex::ScopedLock lock(_statsMutex);
		_stats.sended_rst++;
	}

	void inc_ip_packets()
	{
		Poco::Mutex::ScopedLock lock(_statsMutex);
		_stats.ip_packets++;
	}

	void inc_total_bytes(uint32_t bytes)
	{
		Poco::Mutex::ScopedLock lock(_statsMutex);
		_stats.total_bytes += bytes;
	}

	void inc_total_bytes_packets(uint32_t bytes)
	{
		Poco::Mutex::ScopedLock lock(_statsMutex);
		_stats.total_bytes += bytes;
		_stats.ip_packets++;
	}

	void inc_matched_ssl()
	{
		Poco::Mutex::ScopedLock lock(_statsMutex);
		_stats.matched_ssl++;
	}

	void inc_matched_ssl_ip()
	{
		Poco::Mutex::ScopedLock lock(_statsMutex);
		_stats.matched_ssl_ip++;
	}

	void inc_matched_ip_port()
	{
		Poco::Mutex::ScopedLock lock(_statsMutex);
		_stats.matched_ip_port++;
	}
private:
	Poco::Logger& _logger;
	struct nfq_q_handle *qh;
	int _queue_maxlen;
	struct nfqConfig _config;
	struct threadStats _stats;
	Poco::Mutex _statsMutex;

	Poco::NotificationQueue queue;
	std::vector<PktAnalyzer *> _workThreads;
};

#endif
