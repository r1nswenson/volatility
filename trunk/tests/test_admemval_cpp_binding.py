import logging
import ntpath
from unittest import TestCase

from admemval import TestFunction, TestClass, AdPefileClass
from winappdbg import System
from admem.admemoryvalidator import MemoryValidatorClass
from perf import CounterMonitorClass, UpdateCounterForScope

CounterMonitor = CounterMonitorClass('test_memory_validator_with_winappdbg.db')

logging.basicConfig(level=logging.WARN, format="%(filename)s::%(lineno)d::%(message)s")

class TestAdMemVal(TestCase):
    def testFunctionCall(self):
        name, age = TestFunction('rajesh', 'sharma', 100)
        logging.info('name: {} age:{}'.format(name, age))
        self.assertTrue(name and age, 'test failed')

    def testClassCall(self):
        testClass = TestClass('rajesh', 'sharma', 100)
        name, age = testClass.GetInfo()
        logging.info('name: {} age:{}'.format(name, age))
        self.assertTrue(name and age, 'test failed')

    def testAdPelibClass(self):
        pefile = AdPefileClass()
        good = pefile.LoadFile('c:\\windows\\system32\\notepad.exe')
        self.assertTrue(good, 'test failed')
        pefile.dumpMzHeader()
        pefile.dumpPeHeader()
        pefile.dumpExportDirectory()
        pefile.dumpImportDirectory()

    #PROCESS_TO_SCAN = ['eat_exe', 'iat_exe', 'test_minhook']
    #PROCESS_TO_SCAN = ['explorer']
    PROCESS_TO_SCAN = ['exe']
    def testRunningProcesses(self):
        validator = MemoryValidatorClass()
        validator.Initialize('c:\\mem\\user\\')
        CounterMonitor.Start()
        System.request_debug_privileges()
        with UpdateCounterForScope('main'):
            system = System()
            system.scan_processes()
            totalProcesses = system.get_process_count()
            for processIndex, process in enumerate(system.iter_processes()):
                fileName = getattr(process, 'fileName')
                pid = getattr(process, 'dwProcessId')
                if not fileName or not pid:
                    continue
                validator.ImageName = fileName
                logging.info("---------------------------------------------")
                validator.Message = "[{}] fileName:{} pid:{}".format(processIndex, fileName, pid)
                logging.info(validator.Message)
                if not any(s in fileName for s in self.PROCESS_TO_SCAN):
                    continue
                print '------process {}/{} {}-------'.format(processIndex, totalProcesses, fileName)
                with validator.ExceptionHandler('Failed comparing {0}'.format(fileName)):
                    process.scan_modules()
                    mods = {}
                    for module in process.iter_modules():
                        baseDllName = ntpath.basename(module.get_filename().lower())
                        mod = {
                            'BaseDllName' : baseDllName,
                            'FullDllName' : module.get_filename().lower(),
                            'StartAddr' : module.get_base(),
                            'EndAddr' : module.get_base() + module.get_size(),
                            'SizeOfImage' : module.get_size()
                        }
                        if not mods.get(baseDllName):
                            mods[baseDllName] = []
                        mods[baseDllName].append(mod)
                    validator.BuildLoadedModuleAddressesFromWinAppDbg(mods)
                    totalMods = len(mods)
                    for modIndex, modList in enumerate(mods.itervalues()):
                        print 'module {}/{} {}'.format(modIndex, totalMods, modList[0]['BaseDllName'])
                        for modIndex, mod in enumerate(modList):
                            validator.InitializeModuleInfoFromWinAppDbg(mod)
                            with validator.ExceptionHandler('failed comparing {0}'.format(mod)):
                                memoryData = process.read(validator.DllBase, validator.SizeOfImage)
                                if not memoryData:
                                    validator.Warn('failed to read memory data')
                                    continue
                                validator.CompareExe(memoryData, validator.FullDllPath)
        CounterMonitor.Stop()
        validator.DumpFinalStats()
