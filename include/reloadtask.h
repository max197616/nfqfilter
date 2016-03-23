
#ifndef __RELOAD_TASK_H
#define __RELOAD_TASK_H

#include <Poco/Event.h>
#include <Poco/Task.h>
#include <Poco/Logger.h>

class nfqFilter;

class ReloadTask: public Poco::Task
{

public:
	ReloadTask(nfqFilter *parent);
	~ReloadTask();

	void runTask();
	void OutStatistic();


	static Poco::Event _event;

private:
	nfqFilter *_parent;
	Poco::Logger& _logger;
};

#endif
