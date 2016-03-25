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

#include <stdint.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>

#include "nfqthread.h"
#include "main.h"

#include "pktanalyzer.h"

nfqThread::nfqThread(struct nfqConfig& cfg):
	Task("nfqThread"),
	_logger(Poco::Logger::get("nfqThread")),
	_queue_maxlen(cfg.max_pending_packets*NFQ_BURST_FACTOR),
	_config(cfg)
{
	_stats={0};
}

void nfqThread::getStats(threadStats &st)
{
	Poco::Mutex::ScopedLock lock(_statsMutex);
	st=_stats;
}

void nfqThread::runTask()
{
	struct nfq_handle *h;
	struct nfnl_handle *nh;
	int fd,rv;
	struct timeval tv;
	int opt;

	char *buf;
	buf=(char *)calloc(1,T_DATA_SIZE);
	if(buf == NULL)
	{
		_logger.error("Unable to get memory for buffer");
		return ;
	}

	_logger.debug("Trying to open nfq library");
	if(!(h = nfq_open()))
	{
		_logger.fatal("Error during nfq_open");
		return ;
	}

	if(nfq_unbind_pf(h,AF_INET6) < 0)
	{
		_logger.fatal("Error during nfq_unbind_pf()");
		return ;
	}

	if(nfq_bind_pf(h,AF_INET6) < 0)
	{
		_logger.fatal("Error during nfq_bind_pf");
		return ;
	}

	_logger.information("NFQ: Binding to queue %d",_config.queueNumber);

	qh = nfq_create_queue(h,_config.queueNumber,&nfqueue_cb,this);

	if(!qh)
	{
		_logger.fatal("Error during nfq_create_queue");
		return ;
	}

	if(nfq_set_mode(qh,NFQNL_COPY_PACKET,0xffff) < 0)
	{
		_logger.fatal("Can't set packet copy mode");
		return ;
	}

	nh = nfq_nfnlh(h); // netlink handle

	fd = nfnl_fd(nh);

	_logger.information("Setting queue length to %d", _queue_maxlen);
	/* non-fatal if it fails */
	if (nfq_set_queue_maxlen(qh, _queue_maxlen) < 0)
	{
		_logger.warning("can't set queue maxlen: your kernel probably doesn't support setting the queue length");
	}

	/* set netlink buffer size to a decent value */
	nfnl_rcvbufsiz(nh, _queue_maxlen * 1500);
	_logger.information("Setting nfnl bufsize to %d",_queue_maxlen * 1500);
	opt=1;

	if(setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int)) == -1)
	{
		_logger.warning("Can't set netlink enobufs: %s", strerror(errno));
	}
	/* Set some netlink specific option on the socket to increase performance */
	opt = 1;
	if (setsockopt(fd, SOL_NETLINK, NETLINK_BROADCAST_SEND_ERROR, &opt, sizeof(int)) == -1)
	{
		_logger.warning("Can't set netlink broadcast error: %s",strerror(errno));
	}
	/* set a timeout to the socket so we can check for a signal
	* in case we don't get packets for a longer period. */
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	if(::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1)
	{
		_logger.warning("can't set socket timeout: %s",strerror(errno));
	}

	Poco::ThreadPool threadpool("PktAnalyzerPool");
	for(int i=1; i <= _config.num_threads; i++)
	{
		PktAnalyzer *thread=new PktAnalyzer("PktAnalyzer "+std::to_string(i),queue,_config,this);
		_workThreads.push_back(thread);
		threadpool.start(*thread);
	}

	while(!isCancelled())
	{
		if((rv=::recv(fd,buf,T_DATA_SIZE,0)) >= 0)
		{
			// посылаем пакет в наш callback
			try
			{
				nfq_handle_packet(h,buf,rv);
			} catch (Poco::Exception &excep)
			{
				time_t ttm=time(NULL);
				std::string s=std::to_string(ttm);
				Poco::FileOutputStream pdump("/tmp/packet_dump"+s,std::ios::binary);
				for(int i=0; i < rv; i++)
				{
					pdump << (unsigned char) buf[i];
				}
				pdump.close();
				_logger.error("Got exception: %s:%s",excep.message(),excep.what());
			} catch (...)
			{
				_logger.error("Unknown exception!");
			}
			continue;
		} else if(rv == -1) {
			if(errno == EWOULDBLOCK)
			{
				// всего лишь таймаут, ждем снова...
				continue;
			}
			// выходим из цикла...
			if(errno == EINTR)
			{
				break;
			}
			switch(errno)
			{
				case EAGAIN:
					_logger.error("ERROR: EAGAIN"); break;
				case EBADF:
					_logger.error("ERROR: EBADF: Bad file descriptor"); break;
				case ECONNRESET:
					_logger.error("ERROR: ECONNRESET: NFQ socket connection reset"); break;
				case ETIMEDOUT:
					_logger.error("ERROR: ETIMEDOUT: NFQ socket connection timedout"); break;
				case ENOBUFS:
					_logger.error("ERROR: ENOBUFS: Application is not fast enough. Increase socket buffer size by nfnl_rcvbufsize()"); break;
				default:
					_logger.error("Unknown error code %d",errno); break;
			}
		}
	}
	while(!queue.empty()) Poco::Thread::sleep(100);
	for(auto it=_workThreads.begin(); it != _workThreads.end(); it++)
	{
		(*it)->stop();
	}
	queue.wakeUpAll();
	threadpool.joinAll();
	nfq_destroy_queue(qh);
	nfq_close(h);
	if(buf)
		free(buf);
	_logger.debug("Destroing queue %d",_config.queueNumber);
}


int nfqThread::nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	// указатель на наш объект
	nfqThread *self=(nfqThread *)data;
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);
	self->_logger.debug("Got the packet from queue");
//	if(ph && ph->hook == NF_INET_LOCAL_OUT)
	if(ph && ph->hook == NF_INET_PRE_ROUTING)
	{

		self->queue.enqueueNotification(new PktNotification(qh,ntohl(ph->packet_id),nfa));
		return 0;
	} else {
		if(!ph)
		{
			self->_logger.error("NFQ: Can't get message packet header");
			return 0;
		} else {
			self->_logger.warning("NFQ: Packet not for our callback");
		}
	}
	nfq_set_verdict(qh,ntohl(ph->packet_id),NF_ACCEPT,0,NULL);
	return 0;
}


