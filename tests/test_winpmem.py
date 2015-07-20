import logging
import struct
import win32file
from ctypes import c_longlong
from unittest import TestCase

def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType<<16) | (Access << 14) | (Function << 2) | Method

INFO_IOCTRL = CTL_CODE(0x22, 0x103, 0, 3)

VIRTUAL_ADDRESS_IS_VALID = CTL_CODE(0x22, 0x104, 0, 3)

logging.basicConfig(level=logging.INFO)

class TestWinPmem(TestCase):
    def testPackUnpack(self):
        inputFormat = 'QQ'
        requestInput = struct.pack(inputFormat, 987654, 1234567890)
        pid, va = struct.unpack_from("LQ", requestInput)
        print pid, va

    def testPmem(self):
        self._OpenFileForWrite("\\\\.\\pmem")
        self.ParseMemoryRuns()
        self.TestVirtualAddress()

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
        self.runs = []
        result = win32file.DeviceIoControl(
            self.fhandle, INFO_IOCTRL, "", 102400, None)

        fmt_string = "Q" * len(self.FIELDS)
        self.memory_parameters = dict(zip(self.FIELDS, struct.unpack_from(
            fmt_string, result)))

        self.dtb = self.memory_parameters["CR3"]
        self.process_id = 0
        logging.info("dtb:{0}".format(self.dtb))

        offset = struct.calcsize(fmt_string)

        for x in xrange(self.memory_parameters["NumberOfRuns"]):
            start, length = struct.unpack_from("QQ", result, x * 16 + offset)
            self.runs.append((start, start, length))

    def TestVirtualAddress(self):
        inputFormat = 'QQ'
        requestInput = struct.pack(inputFormat, 987654, 1234567890)
        outputFormat = '?'
        outputSize = struct.calcsize(outputFormat)
        addressIsValid = False
        try:
            responseOutput = win32file.DeviceIoControl(self.fhandle, VIRTUAL_ADDRESS_IS_VALID, requestInput, outputSize, None)
            responseParsed = struct.unpack(outputFormat, responseOutput)
            addressIsValid = responseParsed[0]
            print addressIsValid
        except Exception, e:
            logging.error(e)
