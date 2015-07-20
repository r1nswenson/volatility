import os
import logging
import pefile
from unittest import TestCase

from perf import CounterMonitorClass, UpdateCounterForScope
CounterMonitor = CounterMonitorClass('test_pefile.db')

#logging.basicConfig(level=logging.INFO, format="%(filename)s::%(lineno)d::%(message)s")
logging.basicConfig(level=logging.INFO, format="%(message)s")

current_pid = os.getpid()

class TestPeFile(TestCase):
    def testFile(self):
        path = r"c:\windows\system32\notepad.exe"
        pe = pefile.PE(name=path)
        logging.info(pe)
        self.assertTrue(pe, 'test failed')
