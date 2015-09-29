#ifndef __SENDER_TASK_H
#define __SENDER_TASK_H

#include <Poco/Task.h>
#include <Poco/Mutex.h>
#include <Poco/Notification.h>
#include <Poco/NotificationQueue.h>
#include <Poco/AutoPtr.h>
#include <Poco/Logger.h>
#include <Poco/Net/IPAddress.h>



class RedirectNotification: public Poco::Notification
	// The notification sent to worker threads.
{
public:
	typedef Poco::AutoPtr<RedirectNotification> Ptr;
	
	RedirectNotification(int user_port, int dst_port, Poco::Net::IPAddress &user_ip, Poco::Net::IPAddress &dst_ip, uint32_t acknum, uint32_t seqnum, int f_psh, std::string &additional_param):
		_user_port(user_port),
		_dst_port(dst_port),
		_user_ip(user_ip),
		_dst_ip(dst_ip),
		_acknum(acknum),
		_seqnum(seqnum),
		_f_psh(f_psh),
		_additional_param(additional_param)
	{
	}
	int user_port()
	{
		return _user_port;
	}
	int dst_port()
	{
		return _dst_port;
	}
	Poco::Net::IPAddress &user_ip()
	{
		return _user_ip;
	}
	Poco::Net::IPAddress &dst_ip()
	{
		return _dst_ip;
	}
	u_int32_t acknum()
	{
		return _acknum;
	}
	u_int32_t seqnum()
	{
		return _seqnum;
	}
	int f_psh()
	{
		return _f_psh;
	}
	std::string &additional_param()
	{
		return _additional_param;
	}
private:
	int _user_port;
	int _dst_port;
	Poco::Net::IPAddress _user_ip;
	Poco::Net::IPAddress _dst_ip;
	uint32_t _acknum;
	uint32_t _seqnum;
	int _f_psh;
	std::string _additional_param;
};



class CSender;

/// Данная задача отсылает редирект заданному клиенту
class SenderTask: public Poco::Task
{
public:
	SenderTask(std::string &redirect_url);
	~SenderTask();

	void runTask();

	// очередь, куда необходимо писать отправные данные...
	static Poco::NotificationQueue queue;

private:
	CSender *sender;
	static Poco::FastMutex _mutex;
	Poco::Logger& _logger;
};

#endif
