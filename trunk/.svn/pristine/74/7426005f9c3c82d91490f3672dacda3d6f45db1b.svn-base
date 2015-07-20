__author__ = 'achigurala'
import logging
import addatastructs.sdts_pb2 as datastructs
import volatility.plugins.ssdt as SSDTS
import volatility.utils as utils
from addatastructs import adutils as adutils
import volatility.obj as obj
import volatility.win32.tasks as tasks
from addatastructs.proto2xml import *

class ADSdtGenerator:

    def execute(self,config):
        addr_space = utils.load_as(config)
        syscalls = addr_space.profile.syscalls
        bits32 = addr_space.profile.metadata.get('memory_model', '32bit') == '32bit'
        data = SSDTS.SSDT(config).calculate()
        sdtObjectList = datastructs.rootType()

        # Print out the entries for each table
        for idx, table, n, vm, mods, mod_addrs in data:
            sdtObject = sdtObjectList.SSDTs.SSDT.add()
            sdtObject.VirtAddr=table

            sdtEntries = sdtObject.SSDTEntries
            sdtEntries.count=n

            for i in range(n):
                if bits32:
                    # These are absolute function addresses in kernel memory.
                    syscall_addr = obj.Object('address', table + (i * 4), vm).v()
                else:
                    # These must be signed long for x64 because they are RVAs relative
                    # to the base of the table and can be negative.
                    offset = obj.Object('long', table + (i * 4), vm).v()
                    # The offset is the top 20 bits of the 32 bit number.
                    syscall_addr = table + (offset >> 4)
                try:
                    syscall_name = syscalls[idx][i]
                except IndexError:
                    syscall_name = "UNKNOWN"

                syscall_mod = tasks.find_module(mods, mod_addrs, addr_space.address_mask(syscall_addr))
                if syscall_mod:
                    syscall_modname = syscall_mod.BaseDllName
                else:
                    syscall_modname = "UNKNOWN"

                sdtEntry = sdtEntries.SSDTEntry.add()
                sdtEntry.FunctionName=adutils.SmartUnicode(syscall_name)
                sdtEntry.ModuleName=adutils.SmartUnicode(syscall_modname)
                sdtEntry.VirtAddr=int(syscall_addr)

        sdtsfile = open(config.OUTPUT_PATH + "sdts.xml", "w")
        #sdtsfile.write(sdtObjectList.SerializeToString())
        sdtsfile.write(proto2xml(sdtObjectList,indent=0))

        logging.debug("Completed exporting the sdts on the system")