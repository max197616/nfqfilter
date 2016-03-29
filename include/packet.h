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

#ifndef __PACKET_H
#define __PACKET_H

#include <stdint.h>
#include <sys/time.h>

#define DYNAMIC_MEM

class Packet
{
public:
	Packet(struct nfq_q_handle *qh, int packet_id, struct nfq_data *nfa);
	~Packet();
	inline int get_id()
	{
		return _id;
	}
	inline uint8_t *get_payload()
	{
#ifdef DYNAMIC_MEM
		return _ext_pkt;
#else
		return &_ext_pkt[0];
#endif
	}
	inline uint32_t get_size()
	{
		return _pktlen;
	}
	inline struct nfq_q_handle *get_qh()
	{
		return _qh;
	}
private:

	struct nfq_q_handle *_qh;

	int _id; /* номер пакета в nfq*/

	uint32_t _pktlen;

#ifdef DYNAMIC_MEM
	uint8_t *_ext_pkt;
#else
	uint8_t _ext_pkt[2000];
#endif

	struct timeval _ts;
};

#endif
