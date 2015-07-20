import os
import logging
from unittest import TestCase

from admem.admemoryvalidator import MemoryValidatorClass
from perf import CounterMonitorClass, UpdateCounterForScope

CounterMonitor = CounterMonitorClass('test_memory_validation_with_vol.db')

import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace

import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.plugins.modules as modules

config = conf.ConfObject()
registry.register_global_options(config, commands.Command)
registry.register_global_options(config, addrspace.BaseAddressSpace)
config.parse_options()
config.PROFILE="Win7SP1x64"
config.LOCATION="\\\\.\\pmem"
config.process_id = 0
config.dtb = None

logging.basicConfig(level=logging.WARN, format="%(filename)s::%(lineno)d::%(message)s")

current_pid = os.getpid()

class TestMemoryValidatorClass(TestCase):
    def testAllKernelModulesInMemoryToFilesOnDisk(self):
        validator = MemoryValidatorClass()
        validator.Initialize('c:\\mem\\kernel\\')
        CounterMonitor.Start()
        with UpdateCounterForScope('main'):
            addr_space = utils.load_as(config)
            all_mods = modules.Modules(config).calculate()
            validator.BuildLoadedModuleAddressesFromVol(all_mods)
            for mod in all_mods:
                with validator.ExceptionHandler('Failed comparing {0}'.format(mod)):
                    validator.InitializeModuleInfoFromVol(mod)
                    #bytearray is fast but screwing up pefile
                    #memoryData = bytearray(addr_space.zread(self.DllBase, self.size_to_read))
                    memoryData = addr_space.zread(validator.DllBase, validator.SizeOfImage)
                    if not memoryData:
                        logging.error('failed to read memory data for {0}'.format(validator.FullDllPath))
                        continue
                    validator.CompareExe(memoryData, validator.FullDllPath)
        CounterMonitor.Stop()
        validator.DumpFinalStats()

    #PROCESS_TO_SCAN = ['eat_exe', 'iat_exe', 'test_minhook']
    PROCESS_TO_SCAN = ['exe']
    def testAllProcessMemoryWithFilesOnDisk(self):
        validator = MemoryValidatorClass()
        validator.Initialize('c:\\mem\\user\\')
        CounterMonitor.Start()
        with UpdateCounterForScope('main'):
            addr_space = utils.load_as(config)
            processList = tasks.pslist(addr_space)
            for processIndex, eprocess in enumerate(processList):
                imagename = str(eprocess.ImageFileName).lower()
                logging.info("---------------------------------------------")
                validator.Message = "ImageFileName:{0} UniqueProcessId:{1} DirectoryTableBase:{2}".format(eprocess.ImageFileName, eprocess.UniqueProcessId, eprocess.Pcb.DirectoryTableBase)
                if not any(s in imagename for s in self.PROCESS_TO_SCAN):
                    continue
                validator.ImageName = imagename
                print '------process {} {}-------'.format(processIndex, imagename)
                config.process_id = eprocess.UniqueProcessId
                config.dtb = eprocess.Pcb.DirectoryTableBase

                task_space = eprocess.get_process_address_space()
                if not task_space:
                    logging.error("Cannot acquire process AS")
                    continue

                all_mods = list(eprocess.get_load_modules())
                # PEB is paged out or no DLLs loaded
                if not all_mods:
                    logging.error("Cannot load DLLs in process AS")
                    continue
                validator.BuildLoadedModuleAddressesFromVol(all_mods)
                totalMods = len(all_mods)
                for modIndex, mod in enumerate(all_mods):
                    print 'module {}/{} {}'.format(modIndex, totalMods, str(mod.BaseDllName))
                    with validator.ExceptionHandler('Failed comparing {0}'.format(imagename)):
                        validator.InitializeModuleInfoFromVol(mod)
                        if not task_space.is_valid_address(validator.DllBase):
                            logging.error("Address is not valid in process AS")
                            continue
                        memoryData = task_space.zread(validator.DllBase, validator.SizeOfImage)
                        if not memoryData:
                            validator.Warn('failed to read memory data')
                            continue
                        validator.CompareExe(memoryData, validator.FullDllPath)
        CounterMonitor.Stop()
        validator.DumpFinalStats()
