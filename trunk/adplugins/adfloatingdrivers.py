import os
from admem.adutils import ExpandPath
from adplugins.adcommon import AdPluginClass, FileOutputClass
from perf.counter import UpdateCounterForScope
import addatastructs.floatingdrivers_pb2 as datastructs
import volatility.plugins.modules as modules
import addatastructs.adutils as utils
import logging
from addatastructs.proto2xml import *

class ADFloatingDriver(AdPluginClass):
    operation_name = 'floatingdrivers'

    def execute(self, options, config):
        with UpdateCounterForScope('ADFloatingDriver'):
            output = FileOutputClass(getattr(config, "OUTPUT_PATH"), type(self).operation_name)
            if not output.Open():
                return

            data = modules.Modules(config).calculate()

            floatingDrivers = datastructs.rootType()
            for module in data:
                driverName = utils._utf8_encode(module.BaseDllName)
                driverPath = utils._utf8_encode(module.FullDllName)
                driverFullPath = ExpandPath(driverPath)
                if not os.path.exists(driverFullPath):
                    driver = floatingDrivers.FloatingDriver.add()
                    driver.Name = driverName
                    driver.Path = driverFullPath

            output.File.write(proto2xml(floatingDrivers, indent=0))
            output.Close()