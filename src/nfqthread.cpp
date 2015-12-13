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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <istream>
#include <streambuf>

#include "nfqthread.h"
#include "main.h"
#include <Poco/Net/HTTPRequest.h>
#include <Poco/URI.h>
#include <Poco/Stopwatch.h>
#include <Poco/Net/IPAddress.h>
#include "AhoCorasickPlus.h"

#include <libndpi/ndpi_api.h>
#include <memory>

#include "sendertask.h"

#define iphdr(x)	((struct iphdr *)(x))
#define tcphdr(x)	((struct tcphdr *)(x))



//#define OLD_DPI 1

//#define DEBUG_EXCEPTION 1

struct membuf : std::streambuf
{
	membuf(char* begin, char* end)
	{
		this->setg(begin, begin, end);
	}
};

nfqThread::nfqThread(struct nfqConfig& cfg):
	Task("nfqThread"),
	_logger(Poco::Logger::get("nfqThread")),
	_config(cfg),
	_queue_maxlen(cfg.max_pending_packets*NFQ_BURST_FACTOR)
{
	memset(&_stats,0,sizeof(struct threadStats));
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
	buf=(char *)malloc(T_DATA_SIZE);
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
					_logger.error("ERROR: ETIMEDOUT: NFQ soeckt connection timedout"); break;
				case ENOBUFS:
					_logger.error("ERROR: ENOBUFS: Application is not fast enough. Increase socket buffer size by nfnl_rcvbufsize()"); break;
				default:
					_logger.error("Unknown error code %d",errno); break;
			}
		}
	}
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
		Poco::Stopwatch sw;
		int id=0;
		int size=0;
		unsigned char *full_packet;

		id = ntohl(ph->packet_id);
		size = nfq_get_payload(nfa,&full_packet);

		//int id_protocol = full_packet[9];
		struct ip *iph = (struct ip *)full_packet;
		struct ip6_hdr *iph6 = (struct ip6_hdr *)full_packet;

		// определяем версию протокола
		int ip_version=0;
		if(iph->ip_v == 6)
			ip_version = 6;
		else if (iph->ip_v == 4)
			ip_version = 4;
		if(!ip_version)
		{
			self->_logger.error("Unsupported IP protocol version %d for packet id %d",(int) iph->ip_v, id);
			nfq_set_verdict(qh,id,NF_ACCEPT,0,NULL);
			return 0;
		}

		unsigned char *pkt_data_ptr = NULL;
		struct tcphdr* tcph;

		pkt_data_ptr = full_packet + (ip_version == 4 ? sizeof(struct ip) : sizeof(struct ip6_hdr));

		tcph = (struct tcphdr *) pkt_data_ptr;

		// длина ip заголовка
		int iphlen = iphdr(full_packet)->ihl*4; // ipv4
		if(ip_version == 6)
			iphlen = sizeof(struct ip6_hdr);

		// длина tcp заголовка
		int tcphlen = tcphdr(full_packet+iphlen)->doff*4;

		// общая длина всех заголовков
		int hlen = iphlen + tcphlen;

		// пропускаем пакет без данных
		if(hlen == size)
		{
			nfq_set_verdict(self->qh,id,NF_ACCEPT,0,NULL);
			return 0;
		}

		if(ip_version == 4)
		{
			// проверяем из списка hosts ipv4...
			IPPortMap::Iterator it_ip=nfqFilter::_ipportMap.find(iph->ip_dst.s_addr);
			if(it_ip != nfqFilter::_ipportMap.end())
			{
				unsigned short port=ntohs(tcph->dest);
				if (it_ip->second.find(port) != it_ip->second.end())
				{
					if(self->_config.send_rst)
					{
						Poco::Net::IPAddress src_ip(&iph->ip_src,sizeof(in_addr));
						Poco::Net::IPAddress dst_ip(&iph->ip_dst,sizeof(in_addr));
						int tcp_src_port=ntohs(tcph->source);
						int tcp_dst_port=ntohs(tcph->dest);
						self->_logger.debug("HostList: Send RST to the client (%s) and server (%s) (packet no %d)",src_ip.toString(),dst_ip.toString(),id);
						std::string empty_str;
						SenderTask::queue.enqueueNotification(new RedirectNotification(tcp_src_port, tcp_dst_port,&src_ip, &dst_ip,/*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq,/* flag psh */ (tcph->psh ? 1 : 0 ),empty_str,true));
						Poco::Mutex::ScopedLock lock(self->_statsMutex);
						self->_stats.sended_rst++;
						nfq_set_verdict(self->qh,id,NF_DROP,0,NULL);
					} else {
						self->_logger.debug("HostList: Set mark %d to packet no %d  port %hu",self->_config.mark_value,id,port);
						Poco::Mutex::ScopedLock lock(self->_statsMutex);
						self->_stats.marked_hosts++;
						nfq_set_verdict2(self->qh,id,NF_ACCEPT,self->_config.mark_value,0,NULL);
					}
					return 0;
				}
			}
		}
		// todo: добавить поиск по ipv6

		// nDPI usage
		uint8_t *dpi_buf=NULL;
		sw.reset();
		sw.start();
		dpi_buf = (uint8_t *)malloc(size);
		if(dpi_buf == NULL)
		{
			self->_logger.error("Can't allocate memory buffer!");
			nfq_set_verdict(self->qh,id,NF_ACCEPT,0,NULL);
			return 0;
		}
		memcpy(dpi_buf,full_packet,size);

		struct ndpi_id_struct *src = NULL;
		struct ndpi_id_struct *dst = NULL;
//		struct ndpi_flow_struct *flow = NULL;
		std::unique_ptr<struct ndpi_flow_struct> flow;

		src = (struct ndpi_id_struct*)malloc(nfqFilter::ndpi_size_id_struct);
		memset(src, 0, nfqFilter::ndpi_size_id_struct);
		dst = (struct ndpi_id_struct*)malloc(nfqFilter::ndpi_size_id_struct);
		memset(dst, 0, nfqFilter::ndpi_size_id_struct);

		flow.reset((struct ndpi_flow_struct *)malloc(nfqFilter::ndpi_size_flow_struct));
		memset(flow.get(), 0, nfqFilter::ndpi_size_flow_struct);

		uint32_t current_tickt = 0;
#ifdef OLD_DPI
		u_int32_t protocol = ndpi_detection_process_packet(nfqFilter::my_ndpi_struct, flow, dpi_buf, size, current_tickt, src, dst);
#else
		ndpi_protocol protocol = ndpi_detection_process_packet(nfqFilter::my_ndpi_struct, flow.get(), dpi_buf, size, current_tickt, src, dst);
#if 0
		// пробуем угадать протокол по портам...
		if(protocol.protocol == NDPI_PROTOCOL_UNKNOWN)
		{
			int tcp_src_port=ntohs(tcph->source);
			int tcp_dst_port=ntohs(tcph->dest);
			self->_logger.information("Guessing protocol...");
			protocol = ndpi_guess_undetected_protocol(nfqFilter::my_ndpi_struct,
							   (ip_version == 4 ? iph->ip_id : iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt),
							   0,//ip
							   tcp_src_port, // sport
							   0,
							   tcp_dst_port); // dport

		}
#endif
		self->_logger.debug("Protocol is %hu/%hu ",protocol.master_protocol,protocol.protocol);
#endif
		sw.stop();
		self->_logger.debug("nDPI protocol detection occupied %ld us",sw.elapsed());
#ifdef OLD_DPI
		if(protocol == NDPI_PROTOCOL_SSL)
#else
		if(protocol.master_protocol == NDPI_PROTOCOL_SSL || protocol.protocol == NDPI_PROTOCOL_SSL)
#endif
		{
			std::string ssl_client;
			std::unique_ptr<Poco::Net::IPAddress> src_ip;
			std::unique_ptr<Poco::Net::IPAddress> dst_ip;
			if(ip_version == 4)
			{
				src_ip.reset(new Poco::Net::IPAddress(&iph->ip_src,sizeof(in_addr)));
				dst_ip.reset(new Poco::Net::IPAddress(&iph->ip_dst,sizeof(in_addr)));
			} else {
				src_ip.reset(new Poco::Net::IPAddress(&iph6->ip6_src,sizeof(in6_addr)));
				dst_ip.reset(new Poco::Net::IPAddress(&iph6->ip6_dst,sizeof(in6_addr)));
			}
			int tcp_src_port=ntohs(tcph->source);
			int tcp_dst_port=ntohs(tcph->dest);
			self->_logger.debug("Analysing SSL protocol");
			if(flow->protos.ssl.client_certificate[0] != '\0')
			{
				ssl_client=flow->protos.ssl.client_certificate;
				self->_logger.debug("SSL client is: %s",ssl_client);
			}
			free(dst);
			free(src);
			free(dpi_buf);
			if(!ssl_client.empty())
			{
				sw.reset();
				sw.start();
				Poco::Mutex::ScopedLock lock(nfqFilter::_sslMutex);
				nfqFilter::atm_ssl->search(ssl_client,false);
				AhoCorasickPlus::Match match;
				bool found=false;
				while(nfqFilter::atm_ssl->findNext(match))
				{
					found=true;
				}
				sw.stop();
				self->_logger.debug("SSL Host seek occupied %ld us, host: %s",sw.elapsed(),ssl_client);
				if(found)
				{
					if(self->_config.send_rst)
					{
						self->_logger.debug("SSLHostList: Send RST to the client (%s) and server (%s) (packet no %d)",src_ip->toString(),dst_ip->toString(),id);
						std::string empty_str;
						SenderTask::queue.enqueueNotification(new RedirectNotification(tcp_src_port, tcp_dst_port,src_ip.get(), dst_ip.get(),/*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq,/* flag psh */ (tcph->psh ? 1 : 0 ),empty_str,true));
						Poco::Mutex::ScopedLock lock(self->_statsMutex);
						self->_stats.sended_rst++;
						nfq_set_verdict(self->qh,id,NF_DROP,0,NULL);
					} else {
						self->_logger.debug("SSLHostList: Set mark %d to packet no %d, ssl host name: %s",self->_config.mark_value,id,ssl_client);
						Poco::Mutex::ScopedLock lock(self->_statsMutex);
						self->_stats.marked_ssl++;
						nfq_set_verdict2(self->qh,id,NF_ACCEPT,self->_config.mark_value,0,NULL);
					}
					return 0;
				}
			} else {
				if(self->_config.block_ssl_no_server)
				{
					struct ndpi_packet_struct *packet_s = &(flow.get())->packet;
					if(packet_s->payload[0] == 0x16 /* Handshake */)
					{
//						u_int16_t total_len  = (packet_s->payload[3] << 8) + packet_s->payload[4] + 5 /* SSL Header */;
						u_int8_t handshake_protocol = packet_s->payload[5]; /* handshake protocol a bit misleading, it is message type according TLS specs */
//						u_int16_t version = packet_s->payload[1];
						if(handshake_protocol == 0x01 /* Client Hello */)
						{
							self->_logger.debug("Blocking/Marking SSL client hello packet from %s to %s", src_ip->toString(), dst_ip->toString());
					
							if(self->_config.send_rst)
							{
								self->_logger.debug("SSLClientHello: Send RST to the client (%s) and server (%s) (packet no %d)",src_ip->toString(),dst_ip->toString(),id);
								std::string empty_str;
								SenderTask::queue.enqueueNotification(new RedirectNotification(tcp_src_port, tcp_dst_port,src_ip.get(), dst_ip.get(),/*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq,/* flag psh */ (tcph->psh ? 1 : 0 ),empty_str,true));
								Poco::Mutex::ScopedLock lock(self->_statsMutex);
								self->_stats.sended_rst++;
								nfq_set_verdict(self->qh,id,NF_DROP,0,NULL);
							} else {
								self->_logger.debug("SSLClientHello: Set mark %d to packet no %d",self->_config.mark_value,id);
								Poco::Mutex::ScopedLock lock(self->_statsMutex);
								self->_stats.marked_ssl++;
								nfq_set_verdict2(self->qh,id,NF_ACCEPT,self->_config.mark_value,0,NULL);
							}
							return 0;
						}
					}
				}
				self->_logger.debug("No ssl client certificate found!");
			}
			nfq_set_verdict(self->qh,id,NF_ACCEPT,0,NULL);
			return 0;
		}
#ifdef OLD_DPI
		if(protocol != NDPI_PROTOCOL_HTTP)
#else
		if(protocol.master_protocol != NDPI_PROTOCOL_HTTP && protocol.protocol != NDPI_PROTOCOL_HTTP)
#endif
		{

			std::unique_ptr<Poco::Net::IPAddress> src_ip;
			std::unique_ptr<Poco::Net::IPAddress> dst_ip;
			if(ip_version == 4)
			{
				src_ip.reset(new Poco::Net::IPAddress(&iph->ip_src,sizeof(in_addr)));
				dst_ip.reset(new Poco::Net::IPAddress(&iph->ip_dst,sizeof(in_addr)));
			} else {
				src_ip.reset(new Poco::Net::IPAddress(&iph6->ip6_src,sizeof(in6_addr)));
				dst_ip.reset(new Poco::Net::IPAddress(&iph6->ip6_dst,sizeof(in6_addr)));
			}
			int tcp_src_port=ntohs(tcph->source);
			int tcp_dst_port=ntohs(tcph->dest);
#ifdef OLD_DPI
			self->_logger.debug("Not http protocol. Protocol is %u from %s:%d to %s:%d",protocol,src_ip->toString(),tcp_src_port,dst_ip->toString(),tcp_dst_port);
#else
			self->_logger.debug("Not http protocol. Protocol is %hu/%hu from %s:%d to %s:%d",protocol.master_protocol,protocol.protocol,src_ip->toString(),tcp_src_port,dst_ip->toString(),tcp_dst_port);
#endif
			free(dst);
			free(src);
			free(dpi_buf);
			nfq_set_verdict(self->qh,id,NF_ACCEPT,0,NULL);
			return 0;
		};

		self->_logger.debug("Got HTTP protocol");

//		self->_logger.debug("Protocol %u/%s",protocol, protocol_name);

		// освобождаем занятую память.
		free(dst);
		free(src);
		free(dpi_buf);

		{

			std::unique_ptr<Poco::Net::IPAddress> src_ip;
			std::unique_ptr<Poco::Net::IPAddress> dst_ip;
			if(ip_version == 4)
			{
				src_ip.reset(new Poco::Net::IPAddress(&iph->ip_src,sizeof(in_addr)));
				dst_ip.reset(new Poco::Net::IPAddress(&iph->ip_dst,sizeof(in_addr)));
			} else {
				src_ip.reset(new Poco::Net::IPAddress(&iph6->ip6_src,sizeof(in6_addr)));
				dst_ip.reset(new Poco::Net::IPAddress(&iph6->ip6_dst,sizeof(in6_addr)));
			}

			int tcp_src_port=ntohs(tcph->source);
			int tcp_dst_port=ntohs(tcph->dest);

			Poco::Net::HTTPRequest request;
			membuf sbuf((char*)full_packet+(ip_version == 4 ? sizeof(struct ip) : sizeof(struct ip6_hdr))+(4*tcph->doff), (char*)full_packet+(ip_version == 4 ? sizeof(struct ip) : sizeof(struct ip6_hdr))+(4*tcph->doff)+size - (tcph->doff*4) - (ip_version == 4 ? sizeof(struct ip) : sizeof(struct ip6_hdr)));
			std::istream in(&sbuf);
			try
			{
				request.read(in);
			} catch (Poco::Exception &excep)
			{
				if(request.getMethod() != Poco::Net::HTTPRequest::HTTP_GET && request.getMethod() != Poco::Net::HTTPRequest::HTTP_POST && request.getMethod() != Poco::Net::HTTPRequest::HTTP_HEAD)
				{
					self->_logger.warning("Got exception %s",excep.message());
					if( self->_config.save_exception_dump)
					{
						time_t ttm=time(NULL);
						std::string s=std::to_string(ttm);
						Poco::FileOutputStream pdump("/tmp/packet_dump_exception-"+s+"-"+src_ip->toString(),std::ios::binary);
						for(int i=0; i < size; i++)
						{
							pdump << (unsigned char) full_packet[i];
						}
						pdump.close();
					}
					nfq_set_verdict(self->qh,id,NF_ACCEPT,0,NULL);
					return 0;
				}
			} catch (...)
			{
				self->_logger.error("Unknown exception !!!");
				nfq_set_verdict(self->qh,id,NF_ACCEPT,0,NULL);
				return 0;
			}
			try
			{
			if((request.getMethod() == Poco::Net::HTTPRequest::HTTP_GET || request.getMethod() == Poco::Net::HTTPRequest::HTTP_POST || request.getMethod() == Poco::Net::HTTPRequest::HTTP_HEAD) && !request.getHost().empty())
			{
				std::string host(request.getHost());
				if(host[host.length()-1] == '.')
				{
					host.erase(host.length()-1,1);
				}
				{
					sw.reset();
					sw.start();
					Poco::Mutex::ScopedLock lock(nfqFilter::_domainMapMutex);
					nfqFilter::atm_domains->search(host,false);
					AhoCorasickPlus::Match match;
					bool found=false;
					while(nfqFilter::atm_domains->findNext(match))
					{
						found=true;
					}
					sw.stop();
					self->_logger.debug("Host seek occupied %ld us",sw.elapsed());
					if(found)
					{
						self->_logger.debug("Host %s present in domain list from ip %s", host, src_ip->toString());
						//std::string add_param("id="+std::to_string(match.id));
						std::string add_param("url="+host);
						SenderTask::queue.enqueueNotification(new RedirectNotification(tcp_src_port, tcp_dst_port, src_ip.get(), dst_ip.get(),/*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq,/* flag psh */ (tcph->psh ? 1 : 0 ),add_param));
						Poco::Mutex::ScopedLock lock(self->_statsMutex);
						self->_stats.redirected_domains++;
						nfq_set_verdict(self->qh,id,NF_DROP,0,NULL);
						return 0;
					}
				}
				{
					sw.reset();
					sw.start();
					Poco::Mutex::ScopedLock lock(nfqFilter::_urlMapMutex);
					std::string uri(host+request.getURI());
					nfqFilter::atm->search(uri,false);
					AhoCorasickPlus::Match match;
					bool found=false;
					while(nfqFilter::atm->findNext(match))
					{
						found=true;
					}
					sw.stop();
					self->_logger.debug("URL seek occupied %ld us for uri %s",sw.elapsed(),uri);
					if(found)
					{
						self->_logger.debug("URL %s present in url (file pos %u) list from ip %s",uri,match.id,src_ip->toString());
						//std::string add_param("id="+std::to_string(match.id));
						std::string add_param("url="+uri);
						SenderTask::queue.enqueueNotification(new RedirectNotification(tcp_src_port, tcp_dst_port,src_ip.get(),dst_ip.get(),/*acknum*/ tcph->ack_seq, /*seqnum*/ tcph->seq,/* flag psh */ (tcph->psh ? 1 : 0 ),add_param));
						Poco::Mutex::ScopedLock lock(self->_statsMutex);
						self->_stats.redirected_urls++;
						nfq_set_verdict(self->qh,id,NF_DROP,0,NULL);
						return 0;
						
					}
				}
			}
			} catch (Poco::NotFoundException &excep)
			{
				self->_logger.warning("Got exсeption: not found key %s",excep.message());
				if(self->_config.save_exception_dump)
				{
					time_t ttm=time(NULL);
					std::string s=std::to_string(ttm);
					Poco::FileOutputStream pdump("/tmp/packet_dump_exception-"+s+"-"+src_ip->toString(),std::ios::binary);
					for(int i=0; i < size; i++)
					{
						pdump << (unsigned char) full_packet[i];
					}
					pdump.close();
				}
			} catch (Poco::Exception &excep)
			{
				self->_logger.warning("Got exception: %s",excep.message());
			}
		}
		nfq_set_verdict(self->qh,id,NF_ACCEPT,0,NULL);
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


