#!/usr/bin/env python

'''
Find all KPCR structs in memory.
'''

import volatility.utils as utils
from volatility.scan import BaseScanner, ScannerCheck
import volatility.obj as obj
import addatastructs.processors_pb2 as datastruct
import volatility.plugins.modules as modules
from adplugins.adcommon import find_module
import struct

# Methods to support scanning memory for the KPCRs.
def _read_i32(addr_space,offset):
    ''' Read a little-endian 32-bit integer. '''
    data = addr_space.read(offset,4)
    return struct.unpack('<I',data)[0]
def _read_i64(addr_space,offset):
    ''' Read a little-endian 64-bit integer. '''
    data = addr_space.read(offset,8)
    return struct.unpack('<Q',data)[0]
def _validate_kpcr32(address_space,address):
    ''' See if there could be a KPCR at this address. '''
    voff = _read_i32(address_space,address+0x1c)
    if (voff&0xfff) != (address&0xfff):
        return False
    prcb = _read_i32(address_space,address+0x20)
    if voff + 0x120 != prcb:
        return False
    if _read_i32(address_space,address+0x44)!=0x010001:
        return False
    for i in range(3):
        if (_read_i32(address_space,address+0x38+i*4)&0x80000000)==0:
            return False
    return True
def _validate_kpcr64(address_space,address):
    ''' See if there could be a KPCR at this address. '''
    voff = _read_i64(address_space,address+0x18)
    if (voff&0xfff) != (address&0xfff):
        return False
    prcb = _read_i64(address_space,address+0x20)
    if voff + 0x180 != prcb:
        return False
    if _read_i32(address_space,address+0x60)!=0x010001:
        return False
    if (_read_i64(address_space,address)&0x8000000000000000)==0:
        return False
    if (_read_i64(address_space,address+8)&0x8000000000000000)==0:
        return False
    if (_read_i64(address_space,address+0x38)&0x8000000000000000)==0:
        return False
    return True

class KPCRCheck(ScannerCheck):
    def __init__(self, address_space):
        super(KPCRCheck,self).__init__(address_space)

    def check(self, address):
        if not self.address_space.is_valid_address(address+0x80):
            return False
        data = self.address_space.read(address,8)
        if (ord(data[4])&0x80)!=0 and _validate_kpcr32(self.address_space,address):
            return True
        if (ord(data[7])&0x80)!=0 and _validate_kpcr64(self.address_space,address):
            return True
        return False

    def skip(self, data, data_offset):
        # Optimization: I'm assuming that KPCRs can only occur at multiples of 0x100. If this turns out not to be true, we'll have to change this.
        return 0x100-data_offset%0x100

class KPCRScanner(BaseScanner):
    def __init__(self, address_space):
        super(KPCRScanner,self).__init__()
        self.address_space = address_space
        self.checks = [('KPCRCheck', dict())]

    def scan(self, offset=0, maxlen=None):
        """Yields instances of _KPCR which potentially match."""
        for hit in super(KPCRScanner, self).scan(address_space=self.address_space, offset=offset, maxlen=maxlen):
            yield obj.Object('_KPCR', offset=hit, vm=self.address_space)

def FindKPCR(address_space):
    ''' Scans kernel address space for all KPCR structs. Slow, but finds them all. '''
    scanner = KPCRScanner(address_space=address_space)
    return scanner.scan()

def doProcessors(config):
    ''' Retrieve IDT data. '''

    physical_address_space = utils.load_as(config)
    kernel_address_space = utils.load_as(config,astype='kernel')
    processors_obj = datastruct.rootType()
    proc_num = 0
    for kpcr in FindKPCR(physical_address_space):
        processor_obj = processors_obj.Processor.add()
        processor_obj.ID = proc_num
        proc_num += 1
        IdtBase = kpcr.IdtBase
        IDTs = obj.Array(None,physical_address_space.address_mask(IdtBase.v()),physical_address_space,count=256,target=IdtBase.target)
        for idt in IDTs:
            entry_obj = processor_obj.InterruptDescriptorTable.IDTEntry.add()
            iswin32 = not idt.m('OffsetMiddle')
            if iswin32:
                idttype = idt.Access & 0x1f
                if idt.Access >= 256 or (idt.Access & 0x80) != 0x80:
                    entry_obj.InvalidGate = ''
                elif idttype==0x5:
                    entry_obj.TaskGate = ''
                elif idttype==0x6 or idttype==0xe:
                    entry_obj.InterruptGate = ''
                elif idttype==0x7 or idttype==0xf:
                    entry_obj.TrapGate = ''
                else:
                    entry_obj.InvalidGate = ''
                entry_obj.Address = (idt.ExtendedOffset << 16) | idt.Offset
                entry_obj.Attributes = idt.Access
            else:
                idttype = idt.Type
                if idt.Reserved0!=0 or idt.Reserved1!=0 or idt.Present==0:
                    entry_obj.InvalidGate = ''
                elif idttype==0x5:
                    entry_obj.TaskGate = ''
                elif idttype==0xe:
                    entry_obj.InterruptGate = ''
                elif idttype==0xf:
                    entry_obj.TrapGate = ''
                else:
                    entry_obj.InvalidGate = ''
                entry_obj.Address = ((idt.OffsetHigh & 0xffffffff) << 32) | ((idt.OffsetMiddle & 0xffff) << 16) | (idt.OffsetLow & 0xffff)
                entry_obj.Attributes = (idt.IstIndex << 13) | (idt.Type << 3) | (idt.Dpl<<1) | idt.Present

            entry_obj.Selector = idt.Selector.v()
            module = find_module(config,entry_obj.Address)
            if module:
                entry_obj.Module = module.FullDllName.v()

    return processors_obj

if __name__ == '__main__':
    # For debugging:
    import volatility.conf as conf
    import volatility.registry as registry
    import volatility.commands as commands
    import volatility.addrspace as addrspace
    import volatility.utils as utils

    config = conf.ConfObject()
    registry.register_global_options(config, commands.Command)
    registry.register_global_options(config, addrspace.BaseAddressSpace)
    config.parse_options()
    config.PROFILE = 'Win7SP1x64'
    config.LOCATION = 'file:///svn/volatility/memdump.win7.mem'
    addr_space = utils.load_as(config)

    print doProcessors(addr_space).SerializeToString()
