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



#include "packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>


Packet::Packet(struct nfq_q_handle *qh, int packet_id, struct nfq_data *nfa) : _qh(qh)
{
	int ret;
#ifdef DYNAMIC_MEM
	_ext_pkt=NULL;
#endif
	unsigned char *pktdata;
	_id=packet_id;
	ret = nfq_get_payload(nfa, &pktdata);
	if (ret > 0)
	{
		if (ret > 65536)
		{
			_pktlen=0;
		} else {
			_pktlen=ret;
#ifdef DYNAMIC_MEM
			_ext_pkt = (uint8_t *) calloc(1,ret);
#endif
			memcpy(_ext_pkt,pktdata,ret);
		}
	} else if (ret ==  -1)
	{
		_pktlen=0;
	}
	ret = nfq_get_timestamp(nfa, &_ts);
	if(ret != 0)
	{
		memset(&_ts,0,sizeof(struct timeval));
		gettimeofday(&_ts,NULL);
	}
}

Packet::~Packet()
{
#ifdef DYNAMIC_MEM
	if(_ext_pkt)
	{
		free(_ext_pkt);
	}
#endif
}

