import datetime
import logging
import sqlite3
from counter import Counters
from contextlib import contextmanager
from paths import Paths

class CounterDatabaseClass(object):
    DISABLED = True

    def __init__(self, databaseName):
        self.EpochStartTime = datetime.datetime(1970, 1, 1)
        self.DatabasePath = Paths.GetDatabasePath(databaseName)

    def Initialize(self):
        Counters.Initialize()
        return CounterDatabaseClass.DISABLED or self.CreateTables() and self.InsertCountersInfo()

    @contextmanager
    def DatabaseConnection(self, db):
        try:
            db['connection'] = sqlite3.connect(self.DatabasePath)
            yield
        except (sqlite3.Error, Exception) as e:
            db['success'] = False
            if db['connection']:
                db['connection'].rollback()
            logging.exception(e)
        finally:
            if db['connection']:
                db['connection'].commit()

    def CreateTables(self):
        db = {'connection' : None}
        with self.DatabaseConnection(db):
            connection = db['connection']
            cursor = connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS [CounterData] (
                [LogTime] BIGINT NOT NULL,
                [CounterId] INTEGER NOT NULL,
                [Count] BIGINT,
                [DeltaCount] BIGINT,
                [Time] BIGINT,
                [DeltaTime] BIGINT,
                [Milliseconds] BIGINT,
                [DeltaMilliseconds] BIGINT,
                [Data0] BIGINT,
                [DeltaData0] BIGINT,
                [Data1] BIGINT,
                [DeltaData1] BIGINT);
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS [CounterInfo] (
                [Id] INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                [Description] TEXT NOT NULL);
            """)
            db['success'] = True
        return db['success']

    def InsertCountersInfo(self):
        db = {'connection' : None}
        with self.DatabaseConnection(db):
            connection = db['connection']
            cursor = connection.cursor()
            for counterName in Counters.Map.keys():
                counter = Counters.Get(counterName)
                self.InsertCounterInfo(cursor, counter)
            db['success'] = True
        return db['success']

    def InsertCounterInfo(self, cursor, counter):
        cursor.execute('INSERT OR IGNORE INTO CounterInfo(Id, Description) VALUES(:Id, :Description)',
            {
                'Id':counter.CounterId,
                'Description':counter.Description
            })

    def UpdateCounterData(self):
        if CounterDatabaseClass.DISABLED:
            return True
        db = {'connection' : None}
        with self.DatabaseConnection(db):
            connection = db['connection']
            cursor = connection.cursor()
            for counterName in Counters.Map.keys():
                counter = Counters.Get(counterName)
                counterLast = Counters.GetLast(counterName)
                self.InsertCounterData(cursor, counter, counterLast)
            self.PurgeOldCounterData(cursor, 1)
            db['success'] = True
        return db['success']

    def InsertCounterData(self, cursor, counter, counterLast):
        cursor.execute("""INSERT INTO CounterData(LogTime, CounterId, Count, DeltaCount, Time, DeltaTime, Milliseconds, DeltaMilliseconds, Data0, DeltaData0, Data1, DeltaData1)
                                       VALUES(:LogTime, :CounterId, :Count, :DeltaCount, :Time, :DeltaTime, :Milliseconds, :DeltaMilliseconds, :Data0, :DeltaData0, :Data1, :DeltaData1)""",
            {
                'LogTime':(datetime.datetime.now() - self.EpochStartTime).total_seconds(),
                'CounterId':counter.CounterId,
                'Count':counter.Count,
                'DeltaCount':counter.Count - counterLast.Count,
                'Time':counter.Time,
                'DeltaTime':counter.Time - counterLast.Time,
                'Milliseconds':counter.Time * 1000,
                'DeltaMilliseconds':(counter.Time - counterLast.Time) * 1000,
                'Data0':counter.Data0,
                'DeltaData0':counter.Data0 - counterLast.Data0,
                'Data1':counter.Data0,
                'DeltaData1':counter.Data0 - counterLast.Data0
            })
        counterLast.Set(counter.Count, counter.Time, counter.Data0, counter.Data1)

    def PurgeOldCounterData(self, cursor, cutOffMinutes=60):
        cutOffEpochTime = (datetime.datetime.now() - self.EpochStartTime).total_seconds() - datetime.timedelta(minutes = cutOffMinutes).total_seconds()
        cursor.execute('DELETE FROM CounterData WHERE LogTime < :CutOffEpochTime',
            {
                'CutOffEpochTime': cutOffEpochTime
            })
