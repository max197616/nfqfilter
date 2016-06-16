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

#ifndef __IPACL_H
#define __IPACL_H

#include <Poco/Net/IPAddress.h>
#include <string>
#include <vector>

class IPAclEntry
{
public:
	IPAclEntry(Poco::Net::IPAddress &addr, Poco::Net::IPAddress &msk);
	IPAclEntry(const std::string &description);
	bool parse(const std::string &description);
	bool match(Poco::Net::IPAddress &addr);
	bool isValid();
	std::string toString();

	Poco::Net::IPAddress address;
	Poco::Net::IPAddress mask;
};

class IPAcl
{
public:
	IPAcl();
	IPAclEntry *find(Poco::Net::IPAddress &addr);
	bool add(const std::string &description);

	std::vector<IPAclEntry> acl;
};


#endif
