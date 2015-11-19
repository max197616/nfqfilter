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

#include <iostream>
#include "main.h"
#include "nfqstatistictask.h"
#include "qdpi.h"
#include "AhoCorasickPlus.h"
#include "sendertask.h"
#include "nfqthread.h"

Poco::Mutex nfqFilter::_domainMapMutex;
DomainsMap nfqFilter::_domainsMap;
IPPortMap nfqFilter::_ipportMap;

Poco::Mutex nfqFilter::_urlMapMutex;
DomainsMap nfqFilter::_urlsMap;

Poco::Mutex nfqFilter::_sslMutex;

struct ndpi_detection_module_struct* nfqFilter::my_ndpi_struct = NULL;
u_int32_t nfqFilter::ndpi_size_flow_struct = 0;
u_int32_t nfqFilter::ndpi_size_id_struct = 0;

u_int32_t nfqFilter::current_ndpi_memory = 0;
u_int32_t nfqFilter::max_ndpi_memory = 0;

AhoCorasickPlus *nfqFilter::atm=NULL;

AhoCorasickPlus *nfqFilter::atm_ssl=NULL;


nfqFilter::nfqFilter(): _helpRequested(false),_queueNumber(0),_errorHandler(*this)
{
	Poco::ErrorHandler::set(&_errorHandler);
}

nfqFilter::~nfqFilter()
{
}
void nfqFilter::initialize(Application& self)
{
	loadConfiguration();
	ServerApplication::initialize(self);

	_queueNumber=config().getInt("queue",0);
	_domainsFile=config().getString("domainlist","");
	_urlsFile=config().getString("urllist","");
	_redirectUrl=config().getString("redirect_url","");
	_protocolsFile=config().getString("protocols","");

	std::string _sslFile=config().getString("ssllist","");
	_statistic_interval=config().getInt("statistic_interval",0);
	_max_pending_packets=config().getInt("max_pending_packets",DEFAULT_MAX_PENDING_PACKETS);

	_send_rst=config().getBool("send_rst", false);
	_mark_value=config().getInt("mark_value",MARK_VALUE);


	std::string _hostsFile=config().getString("hostlist","");

	logger().information("Starting up on queue: %d",_queueNumber);
	
	// читаем файл с доменами
	Poco::FileInputStream df(_domainsFile);
	if(df.good())
	{
		int lineno=1;
		while(!df.eof())
		{
			std::string str;
			getline(df,str);
			if(!str.empty())
			{
				std::pair<DomainsMap::Iterator,bool> res=_domainsMap.insert(DomainsMap::ValueType(str,lineno));
				if(res.second)
				{
					logger().debug("Inserted domain: " + str + " from line %d",lineno);
				} else {
					logger().debug("Updated domain: " + str + " from line %d",lineno);
				}
			}
			lineno++;
		}
	} else
		throw Poco::OpenFileException(_domainsFile);
	df.close();

	atm=new AhoCorasickPlus();

	atm_ssl=new AhoCorasickPlus();

	// читаем файл с url
	Poco::FileInputStream uf(_urlsFile);
	if(uf.good())
	{
		int lineno=1;
		while(!uf.eof())
		{
			std::string str;
			getline(uf,str);
			if(!str.empty())
			{
				AhoCorasickPlus::EnumReturnStatus status;
				AhoCorasickPlus::PatternId patId = lineno;
				status = atm->addPattern(str, patId);
				if (status!=AhoCorasickPlus::RETURNSTATUS_SUCCESS)
				{
					if(status == AhoCorasickPlus::RETURNSTATUS_DUPLICATE_PATTERN)
					{
						logger().warning("Pattern %s already present in URL database",str);
					} else {
						logger().error("Failed to add %s from line %d",str,lineno);
					}
				}
			}
			lineno++;
		}
	} else
		throw Poco::OpenFileException(_urlsFile);
	uf.close();


	atm->finalize();


	if(!_sslFile.empty())
	{
		// читаем файл с ssl hosts
		Poco::FileInputStream sslf(_sslFile);
		if(sslf.good())
		{
			int lineno=1;
			while(!sslf.eof())
			{
				std::string str;
				getline(sslf,str);
				if(!str.empty())
				{
					AhoCorasickPlus::EnumReturnStatus status;
					AhoCorasickPlus::PatternId patId = lineno;
					status = atm_ssl->addPattern(str, patId);
					if (status!=AhoCorasickPlus::RETURNSTATUS_SUCCESS)
					{
						if(status == AhoCorasickPlus::RETURNSTATUS_DUPLICATE_PATTERN)
						{
							logger().warning("Pattern %s already present in SSL database",str);
						} else {
							logger().error("Failed to add %s from line %d",str,lineno);
						}
					}
				}
				lineno++;
			}
		} else
			throw Poco::OpenFileException(_sslFile);
		sslf.close();
	}

	atm_ssl->finalize();

	if(!_hostsFile.empty())
	{
		// читаем файл с ssl hosts
		Poco::FileInputStream hf(_hostsFile);
		if(hf.good())
		{
			int lineno=1;
			while(!hf.eof())
			{
				std::string str;
				getline(hf,str);
				if(!str.empty())
				{
					std::string ip=str.substr(0, str.find(":"));
					std::string port=str.substr(str.find(":")+1,str.length());
					logger().debug("IP is %s port %s",ip,port);
					unsigned short porti=atoi(port.c_str());
					struct in_addr _ip;

					inet_pton(AF_INET, ip.c_str(), &_ip);

					IPPortMap::Iterator it=_ipportMap.find(_ip.s_addr);
					if(it == _ipportMap.end())
					{
						std::set<unsigned short> ports;
						ports.insert(porti);
						_ipportMap.insert(IPPortMap::ValueType(_ip.s_addr,ports));
						logger().debug("Inserted ip: " + ip + " port:  " + port + " from line %d",lineno);
					} else {
						logger().debug("Adding port " + port + " from line %d to ip %s",lineno,ip);
						it->second.insert(porti);
					}
					
				}
				lineno++;
			}
		} else
			throw Poco::OpenFileException(_hostsFile);
		hf.close();
	}


	my_ndpi_struct = init_ndpi();

	if (my_ndpi_struct == NULL) {
		logger().error("Can't load nDPI!");
		// TODO вставить отключение ndpi
	}
	if(!_protocolsFile.empty())
	{
		ndpi_load_protocols_file(my_ndpi_struct, (char *)_protocolsFile.c_str());
	}
//	my_ndpi_struct->http_dissect_response=1; // не работает, т.к. у нас нет ответных пакетов от серверов...

	// Load sizes of main parsing structures
	ndpi_size_id_struct   = ndpi_detection_get_sizeof_ndpi_id_struct();
	ndpi_size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();
}

void nfqFilter::uninitialize()
{
	logger().debug("Shutting down");
	ServerApplication::uninitialize();
}

void nfqFilter::defineOptions(Poco::Util::OptionSet& options)
{
	Poco::Util::ServerApplication::defineOptions(options);
	options.addOption(
		Poco::Util::Option("help","h","display help on command line arguments")
			.required(false)
			.repeatable(false)
			.callback(Poco::Util::OptionCallback<nfqFilter>(this,&nfqFilter::handleHelp)));
	options.addOption(
		Poco::Util::Option("config_file","c","specify config file to read")
			.required(true)
			.repeatable(false)
			.argument("file")
			.callback(Poco::Util::OptionCallback<nfqFilter>(this,&nfqFilter::handleOptions)));
}

void nfqFilter::handleOptions(const std::string& name,const std::string& value)
{
	if(name == "config_file")
	{
		loadConfiguration(value);
	}
}

void nfqFilter::handleHelp(const std::string& name,const std::string& value)
{
	_helpRequested=true;
	displayHelp();
	stopOptionsProcessing();
}

void nfqFilter::displayHelp()
{
	Poco::Util::HelpFormatter helpFormatter(options());
	helpFormatter.setCommand(commandName());
	helpFormatter.setUsage("<-c config file> [options]");
	helpFormatter.setHeader("NfQueue filter");
	helpFormatter.format(std::cout);
}

int nfqFilter::main(const ArgVec& args)
{
	if(!_helpRequested)
	{
		Poco::TaskManager tm;
		tm.start(new NFQStatisticTask(_statistic_interval));
		tm.start(new nfqThread(_queueNumber,_max_pending_packets,_mark_value,_send_rst));
		tm.start(new SenderTask(_redirectUrl));
		waitForTerminationRequest();
		tm.cancelAll();
		SenderTask::queue.wakeUpAll();
		tm.joinAll();
	}
	return Poco::Util::Application::EXIT_OK;
}





POCO_SERVER_MAIN(nfqFilter)
