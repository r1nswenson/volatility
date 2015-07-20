import datetime

class StopWatchClass(object):
    def __init__(self):
        self.Reset()

    def Reset(self):
        self.Running = False
        self.StartTime = None
        self.StopTime = None
        self.TimeElapsedSeconds = 0

    def Start(self):
        self.StartTime = datetime.datetime.now()
        self.Running = True

    def Stop(self):
        self.StopTime = datetime.datetime.now()
        self.Running = False
        self.TimeElapsedSeconds = (self.StopTime - self.StartTime).total_seconds()

    def Elapsed(self):
        if not self.StartTime:
            return -1
        elif self.Running:
            currentTime = datetime.datetime.now()
            return (currentTime - self.StartTime).total_seconds()
        else:
            return self.TimeElapsedSeconds

class ScopedStopWatchClass(object):
    def __init__(self, stopWatch):
        self.StopWatch = stopWatch

    def __enter__(self):
        self.StopWatch.Start()

    def __exit__(self, exception_type, exception_val, trace):
        self.StopWatch.Stop()
