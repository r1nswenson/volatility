# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2004,2005,2006 4tphi Research
#
# Authors:
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

""" These are standard address spaces supported by Volatility """
import struct
import volatility.addrspace as addrspace
import volatility.debug as debug #pylint: disable-msg=W0611
import urllib
import os
import logging

import pywintypes
import struct
import win32file
from perf import UpdateCounterForScope

def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType<<16) | (Access << 14) | (Function << 2) | Method

# IOCTLS for interacting with the driver.
INFO_IOCTRL = CTL_CODE(0x22, 0x103, 0, 3)

VIRTUAL_ADDRESS_IS_VALID = CTL_CODE(0x22, 0x104, 0, 3)

PAGE_SHIFT = 12

#pylint: disable-msg=C0111

def write_callback(option, _opt_str, _value, parser, *_args, **_kwargs):
    """Callback function to ensure that write support is only enabled if user repeats a long string
    
       This call back checks whether the user really wants write support and then either enables it
       (for all future parses) by changing the option to store_true, or disables it permanently
       by ensuring all future attempts to store the value store_false.
    """
    if not hasattr(parser.values, 'write'):
        # We don't want to use config.outfile, since this should always be seen by the user
        option.dest = "write"
        option.action = "store_false"
        parser.values.write = False
        for _ in range(3):
            testphrase = "Yes, I want to enable write support"
            response = raw_input("Write support requested.  Please type \"" + testphrase +
                                 "\" below precisely (case-sensitive):\n")
            if response == testphrase:
                option.action = "store_true"
                parser.values.write = True
                return
        print "Write support disabled."

class FileAddressSpace(addrspace.BaseAddressSpace):
    """ This is a direct file AS.

    For this AS to be instantiated, we need

    1) A valid config.LOCATION (starting with file://)

    2) no one else has picked the AS before us
    
    3) base == None (we dont operate on anyone else so we need to be
    right at the bottom of the AS stack.)
    """
    ## We should be the AS of last resort
    order = 100
    def __init__(self, base, config, layered = False, **kwargs):
        addrspace.BaseAddressSpace.__init__(self, base, config, **kwargs)
        self.as_assert(base == None or layered, 'Must be first Address Space')
        self.as_assert(config.LOCATION.startswith("file://"), 'Location is not of file scheme')

        path = urllib.url2pathname(config.LOCATION[7:])
        self.as_assert(os.path.exists(path), 'Filename must be specified and exist')
        self.name = os.path.abspath(path)
        self.fname = self.name
        self.mode = 'rb'
        if config.WRITE:
            self.mode += '+'
        self.fhandle = open(self.fname, self.mode)
        self.fhandle.seek(0, 2)
        self.fsize = self.fhandle.tell()

    # Abstract Classes cannot register options, and since this checks config.WRITE in __init__, we define the option here
    @staticmethod
    def register_options(config):
        config.add_option("WRITE", short_option = 'w', action = "callback", default = False,
                          help = "Enable write support", callback = write_callback)

    def fread(self, length):
        length = int(length)
        return self.fhandle.read(length)

    def read(self, addr, length):
        addr, length = int(addr), int(length)
        try:
            self.fhandle.seek(addr)
        except (IOError, OverflowError):
            return None
        data = self.fhandle.read(length)
        if len(data) == 0:
            return None
        return data

    def zread(self, addr, length):
        data = self.read(addr, length)
        if data is None:
            data = "\x00" * length
        elif len(data) != length:
            data += "\x00" * (length - len(data))
        return data

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval,) = struct.unpack('=I', string)
        return longval

    def get_available_addresses(self):
        # Since the second parameter is the length of the run
        # not the end location, it must be set to fsize, not fsize - 1
        yield (0, self.fsize)

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return 0 <= addr < self.fsize

    def close(self):
        self.fhandle.close()

    def write(self, addr, data):
        if not self._config.WRITE:
            return False
        try:
            self.fhandle.seek(addr)
            self.fhandle.write(data)
        except IOError:
            return False
        return True

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.base == other.base and hasattr(other, "fname") and self.fname == other.fname

#ReadCount = 0
class PmemAddressSpace(addrspace.AbstractRunBasedMemory):
    """ This is a direct pmem AS.

    For this AS to be instantiated, we need

    1) A valid config.LOCATION (starting with \\.\pmem)

    2) no one else has picked the AS before us

    3) base == None (we dont operate on anyone else so we need to be
    right at the bottom of the AS stack.)
    """
    ## We should be the AS of last resort
    order = 100
    def __init__(self, base, config, layered = False, *args, **kwargs):
        self.as_assert(base == None or layered, 'Must be first Address Space on which other ASs could be stacked')
        self.as_assert(config.LOCATION.startswith("\\\\"), 'Location is not of pmem scheme')
        addrspace.AbstractRunBasedMemory.__init__(self, base, config, *args, **kwargs)
        self.runs = []

        path = config.LOCATION
        self.name = path

        logging.info("memory filepath to open {0}".format(path))

        self.fname = self.name
        self.mode = 'rb'
        if config.WRITE:
            self.mode += '+'

        self._OpenFileForWrite(self.fname)
        self.ParseMemoryRuns()
        win32file.SetFilePointer(self.fhandle, 0, 0)

    def _OpenFileForRead(self, path):
        self.fhandle = win32file.CreateFile(
            path,
            win32file.GENERIC_READ,
            win32file.FILE_SHARE_READ,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_ATTRIBUTE_NORMAL,
            None)

    def _OpenFileForWrite(self, path):
        self.fhandle = win32file.CreateFile(
            path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_ATTRIBUTE_NORMAL,
            None)

    FIELDS = (["CR3", "NtBuildNumber", "KernBase", "KDBG"] +
              ["KPCR%02d" % i for i in xrange(32)] +
              ["PfnDataBase", "PsLoadedModuleList", "PsActiveProcessHead"] +
              ["Padding%s" % i for i in xrange(0xff)] +
              ["NumberOfRuns"])

    def ParseMemoryRuns(self):
        result = win32file.DeviceIoControl(
            self.fhandle, INFO_IOCTRL, "", 102400, None)

        fmt_string = "Q" * len(self.FIELDS)
        self.memory_parameters = dict(zip(self.FIELDS, struct.unpack_from(
            fmt_string, result)))

        if not self.get_config().dtb:
            self.dtb = self.memory_parameters["CR3"]
            self.get_config().dtb = self.dtb
        else:
            self.dtb = self.get_config().dtb

        if not self.get_config().process_id:
            self.process_id = 0
            self.get_config().process_id = 0
        else:
            self.process_id = self.get_config().process_id

        logging.debug("PmemAddressSpace dtb:{0} process_id:{1}".format(self.dtb, self.process_id))
        #rajesh
        #self.session.SetParameter("dtb", int(self.dtb))

        offset = struct.calcsize(fmt_string)

        for x in xrange(self.memory_parameters["NumberOfRuns"]):
            start, length = struct.unpack_from("QQ", result, x * 16 + offset)
            #print "FileAddressSpace inserting run start:{0} start:{1} length:{2}".format(start, start, length)
            self.runs.append((start, start, length))

    def virtual_addr_is_valid(self, process_id, vaddr):
        try:
            result = win32file.DeviceIoControl(self.fhandle, VIRTUAL_ADDRESS_IS_VALID, struct.pack('QQ', process_id, vaddr), 1, None)
            return struct.unpack('?', result)[0]
        except Exception, e:
            logging.error(e)
        return False

    def AdGetSize(self):
        return win32file.GetFileSize(self.fhandle)

    # Abstract Classes cannot register options, and since this checks config.WRITE in __init__, we define the option here
    @staticmethod
    def register_options(config):
        config.add_option("WRITE", short_option = 'w', action = "callback", default = False,
                          help = "Enable write support", callback = write_callback)

    def fread(self, length):
        length = int(length)
        _, data = win32file.ReadFile(self.fhandle, length)
        print "fread to read length:{0} actual readd {1}".format(length, len(data))
        return data

    def read(self, addr, length):
        #with UpdateCounterForScope('pmem_read'):
            addr, length = int(addr), int(length)

            #print "seek to addr:{0} and to read length:{1}".format(addr, length)
            win32file.SetFilePointer(self.fhandle, addr, 0)
            _, data = win32file.ReadFile(self.fhandle, length)
            if len(data) == 0:
                return None
            # global  ReadCount
            # if ReadCount % 1024*124*8 == 0:
            #     print "seek to addr:{0} and to read length:{1} actual read {2}".format(addr, length, len(data))
            # ReadCount = ReadCount + 1
            return  data

    def zread(self, addr, length):
        data = self.read(addr, length)
        if data is None:
            data = "\x00" * length
        elif len(data) != length:
            data += "\x00" * (length - len(data))
        return data

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval,) = struct.unpack('=I', string)
        return longval

    #rajesh- from FileAddressSpace
    # def get_available_addresses(self):
    #     # Since the second parameter is the length of the run
    #     # not the end location, it must be set to fsize, not fsize - 1
    #     yield (0, self.fsize)
    #
    # def get_available_addresses(self):
    #     for start, file_address, length in self.runs:
    #         yield start, length

    #rajesh- from rekall
    # def is_valid_address(self, addr):
    #     if addr == None:
    #         return False
    #     return 0 <= addr < self.fsize
    # def is_valid_address(self, addr):
    #     return self.vtop(addr) is not None

    def close(self):
        win32file.CloseHandle(self.fhandle)

    def write(self, addr, data):
        if not self._config.WRITE:
            return False
        length = len(data)
        offset, available_length = self._get_available_buffer(addr, length)
        if offset is None:
            # Do not allow writing to reserved areas.
            return

        to_write = min(len(data), available_length)
        win32file.SetFilePointer(self.fhandle, offset, 0)
        win32file.WriteFile(self.fhandle, data[:to_write])
        return True

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.base == other.base and hasattr(other, "fname") and self.fname == other.fname
