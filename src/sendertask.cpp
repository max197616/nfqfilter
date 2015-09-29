#include "sendertask.h"

#include "sender.h"

Poco::FastMutex SenderTask::_mutex;
Poco::NotificationQueue SenderTask::queue;

SenderTask::SenderTask(std::string &redirect_url):
	Task("SenderTask"),
	sender(new CSender(redirect_url)),
	_logger(Poco::Logger::get("SenderTask"))
{

}


SenderTask::~SenderTask()
{
	delete sender;
}

void SenderTask::runTask()
{
	_logger.debug("Starting SenderTask...");

	while(!isCancelled())
	{
		Poco::Notification::Ptr pNf(queue.waitDequeueNotification());
		if (pNf)
		{
			RedirectNotification::Ptr pRedirectNf = pNf.cast<RedirectNotification>();
			if (pRedirectNf)
			{
				sender->Redirect(pRedirectNf->user_port(), pRedirectNf->dst_port(),pRedirectNf->user_ip(),pRedirectNf->dst_ip(), pRedirectNf->acknum(), pRedirectNf->seqnum(), pRedirectNf->f_psh(), pRedirectNf->additional_param());
			}
		}
	}

	_logger.debug("Stopping SenderTask...");
}

