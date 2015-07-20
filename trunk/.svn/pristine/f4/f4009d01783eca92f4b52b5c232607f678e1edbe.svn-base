import time
import threading
from counter import Counters, CounterClass
from counterdb import CounterDatabaseClass
from stopwatch import StopWatchClass

class CounterMonitorClass(threading.Thread):
    def __init__(self, databaseName):
        threading.Thread.__init__(self)
        self.Started = False
        self.StopEvent = threading.Event()
        self.StopEvent.clear()
        self.CounterDatabase = CounterDatabaseClass(databaseName)
        self.StopWatch = StopWatchClass()

    def Start(self):
        if self.CounterDatabase.Initialize():
            self.StopWatch.Start()
            self.start()
            self.Started = True
            return True
        else:
            return False

    def Stop(self):
        if self.Started:
            self.StopEvent.set()
            self.join(5)
            self.Started = False

    def run(self):
        while not self.StopEvent.isSet() and self.Started:
            self.StopEvent.wait(10)
            self.StopWatch.Stop()
            CounterClass.TotalTime = self.StopWatch.Elapsed()
            self.CounterDatabase.UpdateCounterData()
        Counters.Dump()
