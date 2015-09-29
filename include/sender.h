#ifndef __SENDER_H
#define __SENDER_H

#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <errno.h>
#include <stdio.h>
#include <string>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <Poco/Logger.h>
#include <Poco/Net/IPAddress.h>

class CSender {
public:
	CSender( std::string url );
	~CSender();
	void Redirect(int user_port, int dst_port, Poco::Net::IPAddress &src_ip, Poco::Net::IPAddress &dst_ip, uint32_t acknum, uint32_t seqnum, int f_psh, std::string &additional_param);
	void sendPacket(Poco::Net::IPAddress &ip_from, Poco::Net::IPAddress &ip_to, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, std::string &dt, int f_reset, int f_psh);
	
private:
	unsigned short csum(unsigned short *ptr, int nbytes);
	int s;
	std::string redirect_url;
	std::string rHeader;
	Poco::Logger& _logger;

};


#endif
