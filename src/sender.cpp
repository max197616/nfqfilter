#include "sender.h"
#include <unistd.h>

struct pseudo_header
{
	u_int32_t	source_address;
	u_int32_t	dest_address;
	u_int8_t	placeholder;
	u_int8_t	protocol;
	u_int16_t	tcp_length;
};

CSender::CSender( std::string url ) : _logger(Poco::Logger::get("CSender"))
{
	this->redirect_url = url;
	this->s = ::socket( PF_INET, SOCK_RAW, IPPROTO_TCP );
	if( s == -1 ) {
		_logger.error("Failed to create socket!");
		return;
	}
	int one = 1;
	const int *val = &one;
	if( ::setsockopt(this->s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0 )
	{
		_logger.error("Error setting IP_HDRINCL");
		return;
	}
	this->rHeader = "HTTP/1.1 301 Moved Permanently\nLocation: " + this->redirect_url + "\nConnection: close\n";
}

CSender::~CSender()
{
	::close(s);
}

void CSender::sendPacket(Poco::Net::IPAddress &ip_from, Poco::Net::IPAddress &ip_to, int port_from, int port_to, uint32_t acknum, uint32_t seqnum, std::string &dt, int f_reset, int f_psh)
{
	char datagram[4096], *data, *pseudogram=NULL;
	
	// zero out the packet buffer
	memset(datagram, 0, sizeof(datagram));
	
	// IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	// TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
	struct sockaddr_in sin;
	struct pseudo_header psh;
	
	// Data part
	data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);

	memcpy(data,dt.c_str(),dt.length());
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port_to);
	sin.sin_addr.s_addr=((in_addr *)ip_to.addr())->s_addr;
	
	// Fill the IP header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos=0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
	iph->id = htons(random());
	iph->frag_off = 0;
	iph->ttl = 250;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = ((in_addr *)ip_from.addr())->s_addr;
	iph->daddr = sin.sin_addr.s_addr;
	
	// IP checksum
	iph->check = this->csum((unsigned short *) datagram, iph->tot_len);
	
	// TCP Header
	tcph->source = htons(port_from);
	tcph->dest = htons(port_to);
	tcph->seq = acknum;
	tcph->ack_seq = seqnum;
	tcph->doff = 5;
	tcph->fin = 1;				// !!
	tcph->syn = 0;
	tcph->rst = f_reset;
	tcph->psh = f_psh;
	tcph->ack = 1;
	tcph->urg = 0;
	tcph->window = htons(5840);
	tcph->check = 0;
	tcph->urg_ptr = 0;
	
	psh.source_address = ((in_addr *)ip_from.addr())->s_addr;
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + dt.size() );
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + dt.size();
	pseudogram = (char*)malloc(psize);
	
	memcpy( pseudogram, (char*) &psh, sizeof(struct pseudo_header));
	memcpy( pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + dt.size());
	
	tcph->check = csum( (unsigned short*) pseudogram, psize);
	
	// Send the packet
	if( ::sendto( this->s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0 )
	{
		_logger.error("sendto() failed to %s! ",ip_from.toString());
	}
	if(pseudogram)
		free(pseudogram);

	return;
}

//void CSender::sendPacket(char *ip_from, char *ip_to, int port_from, int port_to, uint32_t acknum, uint32_t seqnum)
void CSender::Redirect(int user_port, int dst_port, Poco::Net::IPAddress &user_ip, Poco::Net::IPAddress &dst_ip, uint32_t acknum, uint32_t seqnum, int f_psh, std::string &additional_param )
{
	// формируем дополнительные параметры
	std::string tstr=rHeader;
	if(!additional_param.empty())
	{
		tstr = "HTTP/1.1 301 Moved Permanently\nLocation: " + this->redirect_url + additional_param + "\nConnection: close\n";
	} else {
		tstr=rHeader;
	}
	this->sendPacket( dst_ip, user_ip, dst_port, user_port, acknum, seqnum, tstr, 0, 0);
	// And reset session with client
//	this->sendPacket( dst_ip, user_ip, dst_port, user_port, acknum, seqnum, redirectHeader, 1, 0);
	
	// And reset session with server
	std::string empty_str;
	this->sendPacket( user_ip, dst_ip, user_port, dst_port, seqnum, acknum, empty_str, 1, f_psh );

	return;
}


unsigned short CSender::csum( unsigned short *ptr, int nbytes )
{
	register long sum;
	unsigned short oddbyte;
	register short answer;
	
	sum = 0;
	while( nbytes > 1 ) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if( nbytes==1 ) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}
	
	sum = (sum>>16)+(sum & 0xffff);
	sum = sum+(sum>>16);
	answer=(short)~sum;
	
	return( answer );
}
