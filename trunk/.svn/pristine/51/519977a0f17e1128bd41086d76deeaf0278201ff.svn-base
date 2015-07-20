__author__ = 'achigurala'

import addatastructs.module_pb2 as datastructs
import volatility.plugins.modules as krnlModules
import volatility.plugins.common as common
import addatastructs.adutils as utils
import logging
from addatastructs.proto2xml import *

class ADKernelModules:
    def execute(self,config):
        data = krnlModules.Modules(config).calculate()
        moduleObjList = datastructs.rootType()
        for module in data:
            moduleObj = moduleObjList.Module.add(resultitemtype=13)
            moduleObj.Name=utils._utf8_encode(module.BaseDllName)
            moduleObj.Path=utils._utf8_encode(module.FullDllName)
            moduleObj.Address=long(module.DllBase.v())
            # This is always 2 in my reference xml from a MemoryAnalysis job.
            # I don't know if that is a mistake, but that doesn't seem useful.
            moduleObj.EntryPoint=long(module.EntryPoint.v())
            moduleObj.Size=int(module.SizeOfImage)
        file = open(config.OUTPUT_PATH + "modules.xml", "w")
        #file.write(moduleObjList.SerializeToString())
        file.write(proto2xml(moduleObjList,indent=0))
        logging.debug("Completed calculating the kernel modules")