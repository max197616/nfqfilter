#ifndef __NFQTHREAD_H
#define __NFQTHREAD_H

#include <Poco/Task.h>
#include <Poco/Logger.h>

#define T_DATA_SIZE 4096

#define NFQ_BURST_FACTOR 4


struct threadStats
{
	u_int64_t marked_ssl;
	u_int64_t redirected_domains;
	u_int64_t redirected_urls;
	u_int64_t marked_hosts;
};

class nfqThread: public Poco::Task
{
public:
	nfqThread(int queueNumber,int max_pending_packets,int mark_value);
	virtual void runTask();
	static int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
	void getStats(threadStats &);

private:
	Poco::Logger& _logger;
	int _queueNumber;
	struct nfq_q_handle *qh;
	int _queue_maxlen;
	int _mark_value;

	struct threadStats _stats;
	Poco::Mutex _statsMutex;
};

#endif
