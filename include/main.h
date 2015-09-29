#ifndef __MAIN_H
#define __MAIN_H

#include "Poco/Util/ServerApplication.h"
#include "Poco/Util/Option.h"
#include "Poco/Util/OptionSet.h"
#include "Poco/Util/HelpFormatter.h"
#include "Poco/Task.h"
#include "Poco/TaskManager.h"
#include "Poco/DateTimeFormatter.h"
#include "Poco/FileStream.h"
#include <Poco/StreamCopier.h>
#include <Poco/HashMap.h>
#include <set>
#include <libndpi/ndpi_api.h>
#include "sender.h"

/* Max packets processed simultaniously per thread. */
#define DEFAULT_MAX_PENDING_PACKETS 1024

// каким значением маркировать пакет, чтобы потом зарезать его файерволом
#define MARK_VALUE 17

typedef Poco::HashMap<std::string,int> DomainsMap;
typedef Poco::HashMap<std::string,int> UrlsMap;

typedef Poco::HashMap<int,std::set<unsigned short>> IPPortMap;

class AhoCorasickPlus;

class nfqFilter: public Poco::Util::ServerApplication
{

public:
	nfqFilter();
	~nfqFilter();

	static Poco::Mutex _domainMapMutex;
	static DomainsMap _domainsMap;
	static IPPortMap _ipportMap;

	static Poco::Mutex _urlMapMutex;
	static UrlsMap _urlsMap;
	static struct ndpi_detection_module_struct* my_ndpi_struct;
	static u_int32_t ndpi_size_flow_struct;
	static u_int32_t ndpi_size_id_struct;
	static AhoCorasickPlus *atm;

	static u_int32_t current_ndpi_memory;
	static u_int32_t max_ndpi_memory;

	static Poco::Mutex _sslMutex;
	static AhoCorasickPlus *atm_ssl;
protected:
	void initialize(Application& self);
	void uninitialize();
	void defineOptions(Poco::Util::OptionSet& options);
	void handleOptions(const std::string& name,const std::string& value);
	void handleHelp(const std::string& name,const std::string& value);
	void displayHelp();
	int main(const ArgVec& args);

private:
	bool _helpRequested;
	std::string _configFile;
	int _queueNumber;
	std::string _domainsFile;
	std::string _urlsFile;
	std::string _redirectUrl;
	std::string _protocolsFile;
	int _bufferSize;
	int _statistic_interval;
	int _max_pending_packets;
	int _mark_value;
};

#endif
