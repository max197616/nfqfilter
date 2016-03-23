
#include "reloadtask.h"
#include "main.h"
#include "AhoCorasickPlus.h"


Poco::Event ReloadTask::_event;


ReloadTask::ReloadTask(nfqFilter *parent):
	Task("ReloadTask"),
	_parent(parent),
	_logger(Poco::Logger::get("ReloadTask"))
{

}


ReloadTask::~ReloadTask()
{
}

void ReloadTask::runTask()
{
	_logger.debug("Starting reload task...");
	while (!isCancelled())
	{
		if(_event.tryWait(300))
		{
			_logger.information("Reloading data from files...");

			AhoCorasickPlus *atm_new = new AhoCorasickPlus();
			DomainsMap *dm_new = new DomainsMap;
			AhoCorasickPlus *to_del_atm;
			DomainsMap *to_del_dm;
			try
			{
				_parent->loadDomains(_parent->getSSLFile(),atm_new,dm_new);
				atm_new->finalize();
				{
					Poco::Mutex::ScopedLock lock(nfqFilter::_sslMutex);
					to_del_atm = nfqFilter::atm_ssl;
					to_del_dm = nfqFilter::_domainsSSLMap;
					nfqFilter::atm_ssl = atm_new;
					nfqFilter::_domainsSSLMap = dm_new;
				}
				delete to_del_atm;
				delete to_del_dm;
				_logger.information("Reloaded data for ssl hosts list");
			} catch (Poco::Exception &excep)
			{
				_logger.error("Got exception while reload ssl data: %s:%s",excep.message(),excep.what());
				delete atm_new;
				delete dm_new;
			}
			

			atm_new = new AhoCorasickPlus();
			dm_new = new DomainsMap;
			try
			{
				_parent->loadDomains(_parent->getDomainsFile(),atm_new,dm_new);
				atm_new->finalize();
				{
					Poco::Mutex::ScopedLock lock(nfqFilter::_domainMapMutex);
					to_del_atm = nfqFilter::atm_domains;
					to_del_dm = nfqFilter::_domainsMap;
					nfqFilter::atm_domains = atm_new;
					nfqFilter::_domainsMap = dm_new;
				}
				delete to_del_atm;
				delete to_del_dm;
				_logger.information("Reloaded data for domains list");
			} catch (Poco::Exception &excep)
			{
				_logger.error("Got exception while reload domains data: %s:%s",excep.message(),excep.what());
				delete atm_new;
				delete dm_new;
			}

			atm_new = new AhoCorasickPlus();
			dm_new = new DomainsMap;
			try
			{
				_parent->loadURLs(_parent->getURLsFile(),atm_new,dm_new);
				atm_new->finalize();
				{
					Poco::Mutex::ScopedLock lock(nfqFilter::_domainMapMutex);
					to_del_atm = nfqFilter::atm;
					to_del_dm = nfqFilter::_domainsUrlsMap;
					nfqFilter::atm = atm_new;
					nfqFilter::_domainsUrlsMap = dm_new;
				}
				delete to_del_atm;
				delete to_del_dm;
				_logger.information("Reloaded data for urls list");
			} catch (Poco::Exception &excep)
			{
				_logger.error("Got exception while reload urls data: %s:%s",excep.message(),excep.what());
				delete atm_new;
				delete dm_new;
			}

			IPPortMap *ip_port_map = new IPPortMap;
			try
			{
				IPPortMap *old;
				_parent->loadHosts(_parent->getHostsFile(),ip_port_map);
				{
					Poco::ScopedWriteRWLock lock(nfqFilter::_ipportMapMutex);
					old = nfqFilter::_ipportMap;
					nfqFilter::_ipportMap = ip_port_map;
				}
				delete old;
				_logger.information("Reloaded data for ip port list");
			} catch (Poco::Exception &excep)
			{
				_logger.error("Got exception while reload ip port data: %s:%s",excep.message(),excep.what());
				delete ip_port_map;
			}

			SSLIps *ssl_ips = new SSLIps;
			try
			{
				_parent->loadSSLIP(_parent->getSSLIpsFile(),ssl_ips);
				SSLIps *ssl_ips_old;
				{
					Poco::ScopedWriteRWLock lock(nfqFilter::_sslIpsSetMutex);
					ssl_ips_old = nfqFilter::_sslIpsSet;
					nfqFilter::_sslIpsSet = ssl_ips;
				}
				delete ssl_ips_old;
				_logger.information("Reloaded data for ssl ip list");
			} catch (Poco::Exception &excep)
			{
				_logger.error("Got exception while reload ip ssl data: %s:%s",excep.message(),excep.what());
				delete ssl_ips;
			}
		}
	}
	_logger.debug("Stopping reload task...");
}
