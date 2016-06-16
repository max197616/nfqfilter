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

#include "ipacl.h"

IPAclEntry::IPAclEntry(const std::string &description):
	address("0.0.0.0"), mask("0.0.0.0")
{
	parse(description);
}

IPAclEntry::IPAclEntry(Poco::Net::IPAddress &addr, Poco::Net::IPAddress &msk):
    address(addr), mask(msk)
{
}

bool IPAclEntry::parse(const std::string &description)
{
	if(description.empty())
		return false;
	std::size_t slash=description.find('/');
	if(slash != std::string::npos)
	{
		std::string addr=description.substr(0,slash);
		std::string msk_t=description.substr(slash+1,description.size());
		if(Poco::Net::IPAddress::tryParse(addr,address))
		{
			int msk = std::stoi(msk_t,nullptr);
			if(address.family() == Poco::Net::IPAddress::IPv4)
			{
				if(msk > 32)
				{
					return false;
				}
				Poco::Net::IPAddress msk1(msk, Poco::Net::IPAddress::IPv4);
				mask=msk1;
			} else {
				if(msk > 128)
				{
					return false;
				}
				mask=Poco::Net::IPAddress(msk,Poco::Net::IPAddress::IPv6);
			}
			return true;
		} else
			return false;
	} else {
		if(Poco::Net::IPAddress::tryParse(description,address))
		{
			if(address.family() == Poco::Net::IPAddress::IPv4)
				mask=Poco::Net::IPAddress(32,Poco::Net::IPAddress::IPv4);
			else
				mask=Poco::Net::IPAddress(128,Poco::Net::IPAddress::IPv6);
		} else
			return false;
	}
}

std::string IPAclEntry::toString()
{
	std::string res=address.toString()+"/"+std::to_string(mask.prefixLength());
	return res;
}

bool IPAclEntry::match(Poco::Net::IPAddress &addr)
{
	if(address.family() != addr.family())
		return false;
	if(address.family() == Poco::Net::IPAddress::IPv4)
		return (address & mask) == (addr & mask);
	int pflen=mask.prefixLength();
	uint32_t oct,bit;
	for(int i=0; i < pflen; i++)
	{
		oct=i/8;
		bit=7-(i%8);
		if((((struct in6_addr *) address.addr())->s6_addr[oct] & (1<<bit)) != (((struct in6_addr *)addr.addr())->s6_addr[oct] & (1<<bit)))
		{
			return false;
		}
	}
	return true;
}

bool IPAclEntry::isValid()
{
	if(address.isWildcard() && mask.isWildcard())
		return false;
	return true;
}

IPAcl::IPAcl()
{
}

IPAclEntry *IPAcl::find(Poco::Net::IPAddress &addr)
{
	if(acl.empty())
		return NULL;
	for(std::vector<IPAclEntry>::iterator it=acl.begin(); it != acl.end(); it++)
	{
		IPAclEntry &entry=(*it);
		if(entry.match(addr))
			return &entry;
	}
	return NULL;
}

bool IPAcl::add(const std::string &description)
{
	IPAclEntry entry(description);
	if(entry.isValid())
	{
		acl.push_back(entry);
		return true;
	}
	return false;
}
