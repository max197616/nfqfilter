#ifndef __NFQSTATISTICTASK_H
#define __NFQSTATISTICTASK_H

class NFQStatisticTask: public Poco::Task
{
public:
	NFQStatisticTask(int sec);
	void runTask();
	void OutStatistic();

private:
	// через сколько секунд выводить инфо о потреблении память. 0 - не выводить
	int _sec;
};


#endif
