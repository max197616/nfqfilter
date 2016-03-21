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

#ifndef __PKTANALYZER_H
#define __PKTANALYZER_H

#include <Poco/Notification.h>
#include <Poco/NotificationQueue.h>
#include <Poco/Runnable.h>
#include <Poco/Mutex.h>
#include <Poco/AutoPtr.h>
#include <Poco/Logger.h>

#include "packet.h"
#include "nfqthread.h"

class PktNotification: public Poco::Notification
	// The notification sent to worker threads.
{
public:
	typedef Poco::AutoPtr<PktNotification> Ptr;
	
	PktNotification(Packet &pkt):
		_pkt(pkt)
	{
	}

	PktNotification(struct nfq_q_handle *qh, int packet_id, struct nfq_data *nfa):
		_pkt(qh,packet_id,nfa)
	{
	}

	Packet &pkt()
	{
		return _pkt;
	}

private:
	Packet _pkt;
};


class PktAnalyzer: public Poco::Runnable
	// A worker thread that gets work items
	// from a NotificationQueue.
{
public:
	PktAnalyzer(const std::string& name, Poco::NotificationQueue& queue, struct nfqConfig& cfg, nfqThread *parent);
	void run();
	char from_hex(char ch);
	std::string url_decode(std::string text);
	void stop();
	void analyzer(Packet &pkt);
	void dump_file(unsigned char *buf,uint32_t rv, int pkt_id);
private:
	std::string _name;
	Poco::NotificationQueue& _queue;
	Poco::Logger& _logger;
	mutable Poco::FastMutex _mutex;
	struct nfqConfig _config;

	nfqThread *_parent;
	int _idleTime;
	bool _stopped;
};


#endif
