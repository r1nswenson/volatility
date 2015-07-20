import os
import logging
import volatility.plugins.modules as modules
from bisect import bisect_right

def find_module(config,address):
    class _FindModuleContext():
        def __init__(self,config):
            self.mods = dict((mod.DllBase, mod) for mod in modules.Modules(config).calculate())
            self.mod_addrs = sorted(self.mods.keys())

        def find(self,addr):
            addr = long(addr)
            pos = bisect_right(self.mod_addrs, addr) - 1
            if pos == -1:
                return None
            mod = self.mods[self.mod_addrs[pos]]

            if addr >= mod.DllBase.v() and addr < mod.DllBase.v() + mod.SizeOfImage.v():
                return mod
            return None

    if not hasattr(find_module,'finder'):
        find_module.finder = dict()
    if config not in find_module.finder:
        find_module.finder[config] = _FindModuleContext(config)
    return find_module.finder[config].find(address)

class AdPluginClass(object):
    def execute(self, options, config):
        raise NotImplementedError('Plugin should implement this method')

class FileOutputClass(object):
    def __init__(self, outputDirectory, operationName):
        self.OutputDirectory = outputDirectory or ''
        self.FullPath = os.path.join(self.OutputDirectory, operationName + ".xml")

    def Open(self):
        self.File = None
        try:
            if len(self.OutputDirectory)and not os.path.exists(self.OutputDirectory):
                os.makedirs(self.OutputDirectory)
            self.File = open(self.FullPath, "w")
        except Exception, e:
            logging.exception(e)
        return self.File

    def Close(self):
        if self.File:
            self.File.close()
