#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "main.h"
#include "nfqstatistictask.h"
#include "nfqthread.h"

NFQStatisticTask::NFQStatisticTask(int sec):
	Task("NFQStatisticTask"),
	_sec(sec)
{
}

static std::string formatBytes(u_int32_t howMuch)
{
	char unit = 'B';
	char buf[100];
	int buf_len=sizeof(buf);

	if(howMuch < 1024)
	{
		snprintf(buf, buf_len, "%lu %c", (unsigned long)howMuch, unit);
	} else if(howMuch < 1048576)
	{
		snprintf(buf, buf_len, "%.2f K%c", (float)(howMuch)/1024, unit);
	} else {
		float tmpGB = ((float)howMuch)/1048576;
		if(tmpGB < 1024)
		{
			snprintf(buf, buf_len, "%.2f M%c", tmpGB, unit);
		} else {
			tmpGB /= 1024;
			snprintf(buf, buf_len, "%.2f G%c", tmpGB, unit);
		}
	}
	return std::string(buf);
}

void NFQStatisticTask::OutStatistic()
{
	Poco::Util::Application& app = Poco::Util::Application::instance();
	app.logger().information("nDPI memory (once): %s",formatBytes(sizeof(ndpi_detection_module_struct)));
	app.logger().information("nDPI memory per flow: %s",formatBytes(nfqFilter::ndpi_size_flow_struct));
	app.logger().information("nDPI current memory usage: %s",formatBytes(nfqFilter::current_ndpi_memory));
	app.logger().information("nDPI maximum memory usage: %s",formatBytes(nfqFilter::max_ndpi_memory));

	Poco::TaskManager *pOwner=getOwner();
	if(pOwner)
	{
		Poco::TaskManager::TaskList tl=pOwner->taskList();
		for(Poco::TaskManager::TaskList::iterator it=tl.begin(); it != tl.end(); it++)
		{
			std::string threadName=(*it)->name();
			std::size_t found=threadName.find("nfqThread");
			if(found != std::string::npos)
			{
				// статистика задачи...
				struct threadStats stats;
				Poco::AutoPtr<nfqThread> p=it->cast<nfqThread>();
				p->getStats(stats);
				app.logger().information("Thread '%s': redirected domains %" PRIu64 ", redirected urls: %" PRIu64 ", marked ssl: %" PRIu64 ", marked hosts: %" PRIu64,threadName,stats.redirected_domains,stats.redirected_urls,stats.marked_ssl,stats.marked_hosts);
			}
			app.logger().information("State of task %s is %d", (*it)->name(), (int)(*it)->state());
		}
	}
}

void NFQStatisticTask::runTask()
{
	Poco::Util::Application& app = Poco::Util::Application::instance();
	app.logger().debug("Starting statistic task...");
	int sleep_sec=_sec;
	if(!sleep_sec)
		sleep_sec=1;
	sleep_sec *= 1000;
	while (!isCancelled())
	{
		sleep(sleep_sec);
		if(_sec)
			OutStatistic();
	}
	app.logger().debug("Stopping statistic task...");
}

