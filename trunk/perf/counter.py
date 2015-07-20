import logging
import threading
import stopwatch
from counterlist import CounterList

class Counters:
    Map = {}
    MapLast = {}

    @classmethod
    def Initialize(self):
        counterId = 1
        for counterName, counterDescription in CounterList.List.iteritems():
            Counters.Map[counterName] = CounterClass(counterId, counterName, counterDescription)
            Counters.MapLast[counterName] = CounterClass(counterId, counterName, counterDescription)
            counterId += 1
        return True

    @classmethod
    def GetCounter(self, map, counterName):
        try:
            return map[counterName]
        except Exception, e:
            logging.exception('No counter was found for id :{0}'.format(counterName))
        return None

    @classmethod
    def Get(self, counterName):
        return self.GetCounter(Counters.Map, counterName)

    @classmethod
    def GetLast(self, counterName):
        return self.GetCounter(Counters.MapLast, counterName)

    @classmethod
    def Dump(self):
        for counterName in Counters.Map.keys():
            counter = self.Get(counterName)
            counter.Dump()

class LockAcquired(object):
    def __init__(self, lock):
        self.Lock = lock

    def __enter__(self):
        self.Lock.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.Lock.release()

class CounterClass(object):
    TotalTime = 1

    def __init__(self, counterId, counterName, description):
        self.CounterId = counterId
        self.CounterName = counterName
        self.Description = description
        self.Reset()
        self.Lock = threading.Lock()

    def Reset(self):
        self.Count = 0
        self.Time = 0
        self.Data0 = 0
        self.Data1 = 0

    def Set(self, count, time, data0, data1):
        self.Count = count
        self.Time = time
        self.Data0 = data0
        self.Data1 = data1

    def AddElapsed(self, elapsed):
        with LockAcquired(self.Lock):
            self.Time += elapsed

    def IncrementCount(self):
        with LockAcquired(self.Lock):
            self.Count += 1

    def AddData0(self, data0):
        with LockAcquired(self.Lock):
            self.Data0 += data0

    def AddData1(self, data1):
        with LockAcquired(self.Lock):
            self.Data1 += data1

    def Dump(self):
        percent = '{:.2f}'.format(self.Time*100.0/CounterClass.TotalTime)
        logging.info('CounterId:{0} CounterName:{1} Description:{2} Count:{3} Time:{4} Percent:{5} Data0:{6} Data1:{7}'.format(
            self.CounterId, self.CounterName, self.Description, self.Count, self.Time, percent, self.Data0, self.Data1))

class UpdateCounterForScope:
    def __init__(self, counterName, data0 = 0, data1 = 0):
        self.CounterData = Counters.Get(counterName)
        if self.CounterData:
            self.StopWatch = stopwatch.StopWatchClass()
            self.Data0 = data0
            self.Data1 = data1

    def __enter__(self):
        if self.CounterData:
            self.StopWatch.Start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.CounterData:
            self.StopWatch.Stop()
            self.CounterData.AddElapsed(self.StopWatch.Elapsed())
            self.CounterData.IncrementCount()
            self.CounterData.AddData0(self.Data0)
            self.CounterData.AddData1(self.Data1)