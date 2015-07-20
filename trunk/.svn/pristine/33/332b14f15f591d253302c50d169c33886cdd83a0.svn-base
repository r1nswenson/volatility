import os
import logging
import pefile
import hexdump
import shutil
import itertools
from contextlib import contextmanager
from perf import UpdateCounterForScope
from admem.adutils import ExpandPath, LruCacheClass
from admemval import AdMemoryValidatorClass

LruCache = LruCacheClass(100)

class MemoryValidatorClass(object):
    def __init__(self):
        pass

    @contextmanager
    def ExceptionHandler(self, message):
        try:
            yield
        except:
            if self.Message:
                logging.error(self.Message)
            logging.exception(message)

    def Warn(self, warning):
        if self.Message:
            logging.warn(self.Message)
        logging.warn(warning)

    def DumpFinalStats(self):
        mismatched = self.DosHeaderMismatched + self.NtHeaderMismatched + self.FileHeaderMismatched + self.OptionalHeaderMismatched + self.SectionHeaderMismatched + self.DataDirectoryMismatched + self.TextSectionMismatched
        logging.warn('Matched:{0} Mismatched:{1} MatchedAfterTextRelocation:{2} FilesNotFound:{3} \n'
            'DosHeaderMismatched:{4} NtHeaderMismatched:{5} FileHeaderMismatched:{6} OptionalHeaderMismatched:{7} SectionHeaderMismatched:{8}\n'
            'DataDirectoryMismatched:{9} TextSectionMismatched:{10}\n'.format(
            self.Matched, mismatched, self.MatchedAfterTextRelocation, self.FilesNotFound,
            self.DosHeaderMismatched, self.NtHeaderMismatched, self.FileHeaderMismatched, self.OptionalHeaderMismatched, self.SectionHeaderMismatched,
            self.DataDirectoryMismatched, self.TextSectionMismatched))

    def Initialize(self, dumpFolder):
        try:
            shutil.rmtree(dumpFolder, ignore_errors=True)
            os.makedirs(dumpFolder)
        except Exception, e:
            logging.WARN('Error initializing dumpfolder {0}. {1}'.format(dumpFolder, e))
        self.Message = None
        self.Matched = 0
        self.DosHeaderMismatched = 0
        self.NtHeaderMismatched = 0
        self.FileHeaderMismatched = 0
        self.OptionalHeaderMismatched = 0
        self.SectionHeaderMismatched = 0
        self.DataDirectoryMismatched = 0
        self.TextSectionMismatched = 0
        self.MatchedAfterTextRelocation = 0
        self.FilesNotFound = 0
        self.DumpFolder = dumpFolder

    def InitializeDumpPaths(self, fileName):
        assert self.DumpFolder is not None
        self.File1DumpPath = os.path.join(self.DumpFolder, '{0}-f1.txt'.format(fileName))
        self.File2DumpPath = os.path.join(self.DumpFolder, '{0}-f2.txt'.format(fileName))
        self.File3DumpPath = os.path.join(self.DumpFolder, '{0}-f3.txt'.format(fileName))

    @classmethod
    def DumpToFile(cls, dumpData, filePath):
        pass
        # dumpFile=open(filePath, "w")
        # dumpFile.write(hexdump.hexdump(dumpData, result='return'))
        # dumpFile.close()

    def CompareDosHeader(self, loadedPe, filePe):
        if str(loadedPe.DOS_HEADER) == str(filePe.DOS_HEADER):
            logging.info('DOS_HEADER match')
            return True
        else:
            self.DosHeaderMismatched += 1
            self.Warn('!!!DOS_HEADER does NOT match!!!')
            return False

    def CompareNtHeader(self, loadedPe, filePe):
        if str(loadedPe.NT_HEADERS) == str(filePe.NT_HEADERS):
            logging.info('NT_HEADERS match')
            return True
        else:
            self.NtHeaderMismatched += 1
            self.Warn('!!!NT_HEADERS does NOT match!!!')
            return False

    def CompareFileHeader(self, loadedPe, filePe):
        if str(loadedPe.FILE_HEADER) == str(filePe.FILE_HEADER):
            logging.info('FILE_HEADER match')
            return True
        else:
            self.FileHeaderMismatched += 1
            self.Warn('!!!FILE_HEADER does NOT match!!!')
            return False

    def CompareOptionalHeader(self, loadedPe, filePe):
        oldImageBaseLoadedPe = loadedPe.OPTIONAL_HEADER.ImageBase
        loadedPe.OPTIONAL_HEADER.ImageBase = 0
        oldImageBaseFilePe = filePe.OPTIONAL_HEADER.ImageBase
        filePe.OPTIONAL_HEADER.ImageBase = 0
        headersMatch = str(loadedPe.OPTIONAL_HEADER) == str(filePe.OPTIONAL_HEADER)
        loadedPe.OPTIONAL_HEADER.ImageBase = oldImageBaseLoadedPe
        filePe.OPTIONAL_HEADER.ImageBase = oldImageBaseFilePe
        if headersMatch:
            logging.info('OPTIONAL_HEADER match')
            return True
        else:
            self.OptionalHeaderMismatched += 1
            self.Warn('!!!OPTIONAL_HEADER does NOT match!!!')
            return False

    def CompareSectionHeaders(self, loadedPe, filePe):
        if len(loadedPe.sections) != len(filePe.sections):
            self.SectionHeaderMismatched += 1
            self.Warn('!!!number of section does NOT match!!!')
            return False
        for sectionIndex in xrange(len(loadedPe.sections)):
            sec1 = loadedPe.sections[sectionIndex]
            oldPointerToRelocations = sec1.PointerToRelocations
            oldPointerToLinenumbers = sec1.PointerToLinenumbers
            oldNumberOfRelocations = sec1.NumberOfRelocations
            oldNumberOfLinenumbers = sec1.NumberOfLinenumbers
            sec1.PointerToRelocations = 0
            sec1.PointerToLinenumbers = 0
            sec1.NumberOfRelocations = 0
            sec1.NumberOfLinenumbers = 0
            sec2 = filePe.sections[sectionIndex]
            sectionMatch = str(sec1) == str(sec2)
            sec1.PointerToRelocations = oldPointerToRelocations
            sec1.PointerToLinenumbers = oldPointerToLinenumbers
            sec1.NumberOfRelocations = oldNumberOfRelocations
            sec1.NumberOfLinenumbers = oldNumberOfLinenumbers
            if not sectionMatch:
                self.SectionHeaderMismatched += 1
                if sec1.Name.startswith('UPX'):
                    self.Warn('section:{0} is UPX packed'.format(sectionIndex))
                else:
                    self.Warn('!!!section {0} does NOT match!!!'.format(sectionIndex))
                return False
        logging.info('all section headers match')
        return True

    def DumpImportDirectory(self, pe):
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
              print entry.dll
              for imp in entry.imports:
                print '\t', hex(imp.address), imp.name

    def ContainAddr(self, modsAddr, addr):
        assert modsAddr is not None
        for modAddr in modsAddr:
            startAddr = modAddr['StartAddr']
            endAddr = modAddr['EndAddr']
            if startAddr <= addr <= endAddr:
                return True
        return False

    def ContainAddress(self, dllName, modsAddr, sym):
        dllName = dllName.lower()
        if self.ContainAddr(modsAddr, sym.bound):
            return True
        elif self.ContainAddr(self.Ntdll, sym.bound):
            return True
        for modAddr in modsAddr:
            startAddr = modAddr['StartAddr']
            endAddr = modAddr['EndAddr']
            self.Warn('Detected IAT hook {0}!{1} bound address {2} is NOT in range {3}:{4} '.format(dllName, sym.name, hex(sym.bound), hex(startAddr), hex(endAddr)))
        return False

    def CompareParsedImportDirectories(self, loadedPe, filePe):
        with UpdateCounterForScope('CompareParsedImportDirectories'):
            if hasattr(loadedPe, 'DIRECTORY_ENTRY_IMPORT') != hasattr(filePe, 'DIRECTORY_ENTRY_IMPORT'):
                self.DataDirectoryMismatched += 1
                self.Warn('!!!import directory entries does NOT match!!!')
                return False
            if not hasattr(loadedPe, 'DIRECTORY_ENTRY_IMPORT'):
                return True
            modules1 = loadedPe.DIRECTORY_ENTRY_IMPORT
            modules2 = filePe.DIRECTORY_ENTRY_IMPORT
            if len(modules1) != len(modules2):
                self.DataDirectoryMismatched += 1
                self.Warn('!!!count of import directory modules does NOT match!!!')
                return False
            for (module1,module2) in itertools.izip(modules1, modules2):
                syms1 =  module1.imports
                syms2 =  module2.imports
                if len(syms1) != len(syms2):
                    self.DataDirectoryMismatched += 1
                    self.Warn('!!!number of data directories does NOT match!!!')
                    return False
                modsAddr = self.Mods.get(module1.dll.lower())
                if not modsAddr:
                    #logging.warn('no start and end addr found for {0} \t {1}'.format(module1.dll, module2.dll))
                    continue
                for sym1, sym2 in itertools.izip(syms1, syms2):
                    if sym1.import_by_ordinal:
                        continue
                    if not sym1.bound:
                        continue
                    if self.ContainAddress(module1.dll, modsAddr, sym1):
                        continue
                    self.DataDirectoryMismatched += 1
                    return False
            return True

    def CompareParsedExportDirectories(self, loadedPe, filePe):
        with UpdateCounterForScope('CompareParsedExportDirectories'):
            if hasattr(loadedPe, 'DIRECTORY_ENTRY_EXPORT') != hasattr(filePe, 'DIRECTORY_ENTRY_EXPORT'):
                self.DataDirectoryMismatched += 1
                self.Warn('!!!export directory entries does NOT match!!!')
                return False
            if not hasattr(loadedPe, 'DIRECTORY_ENTRY_EXPORT'):
                return True
            syms1 = loadedPe.DIRECTORY_ENTRY_EXPORT.symbols
            syms2 = filePe.DIRECTORY_ENTRY_EXPORT.symbols
            if len(syms1) != len(syms2):
                self.DataDirectoryMismatched += 1
                self.Warn('!!!count of export directory symbols does NOT match!!!')
                return False
            startAddr = self.DllBase
            endAddr = self.DllBase + self.SizeOfImage
            for (sym1, sym2) in itertools.izip(syms1, syms2):
                if not sym1.name or not sym1.address:
                    continue
                sym1Addr = sym1.address + self.DllBase
                if startAddr <= sym1Addr <= endAddr:
                    continue
                self.Warn('Detected EAT hook {0}!{1} address {2} is NOT in range {3}:{4} '.format(self.BaseDllName, sym1.name, hex(sym1Addr), hex(startAddr), hex(endAddr)))
                self.DataDirectoryMismatched += 1
                return False
            return True

    IMAGE_DIRECTORY_ENTRY_EXPORT = 0
    IMAGE_DIRECTORY_ENTRY_IMPORT = 1
    def CompareImportExportDirectories(self, loadedPe, filePe):
        with UpdateCounterForScope('parse_data_directories_from_file'):
            filePe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'], pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        self.ChangePointerToRawDataWithVirtualAddress()
        with UpdateCounterForScope('parse_data_directories_from_memory'):
            loadedPe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'], pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        return self.CompareParsedImportDirectories(loadedPe, filePe) and  \
               self.CompareParsedExportDirectories(loadedPe, filePe)

    def CompareDataDirectoriesInPython(self, loadedPe, filePe):
        return self.CompareImportExportDirectories(loadedPe, filePe)

    def CompareDataDirectoriesInCpp(self, loadedPe, filePe):
        if not self.Validator.ParsePeStreams(str(self.LoadedPe.__data__), str(self.FilePe.__data__[:len(self.FilePe.__data__)])):
            self.Warn('Failed to parse streams')
            return False
        return self.Validator.CompareImportExportDirectories()

    def CompareDataDirectories(self, loadedPe, filePe):
        with UpdateCounterForScope('CompareDataDirectories'):
            if len(loadedPe.OPTIONAL_HEADER.DATA_DIRECTORY) != len(loadedPe.OPTIONAL_HEADER.DATA_DIRECTORY):
                self.DataDirectoryMismatched += 1
                self.Warn('!!!number of data directories does NOT match!!!')
                return False
            for directoryIndex in xrange(len(loadedPe.OPTIONAL_HEADER.DATA_DIRECTORY)):
                if str(loadedPe.OPTIONAL_HEADER.DATA_DIRECTORY[directoryIndex]) != str(filePe.OPTIONAL_HEADER.DATA_DIRECTORY[directoryIndex]):
                    self.DataDirectoryMismatched += 1
                    self.Warn('!!!directory {0} does not match!!!'.format(directoryIndex))
                    return False
            if self.UseCpp:
                match =  self.CompareDataDirectoriesInCpp(loadedPe, filePe)
            else:
                match = self.CompareDataDirectoriesInPython(loadedPe, filePe)
            if match:
                logging.info('all data directories match')
            else:
                self.DataDirectoryMismatched += 1
                self.Warn('!!!data directories does NOT match!!!')
            return match

    def GetDataDirectoriesInTextSection1(self, ohdd1, ts1):
        ddList = []
        for index, dd in enumerate(ohdd1):
            if ts1.VirtualAddress <= dd.VirtualAddress <= (ts1.VirtualAddress + ts1.SizeOfRawData):
              ddList.append((dd.VirtualAddress, dd.Size))
        return ddList

    def GetTextSectionData1(self, d1, ddList1, ts1):
        if ts1.VirtualAddress >= len(d1):
            self.Warn('Invalid data')
            return None
        if ts1.VirtualAddress + ts1.SizeOfRawData >= len(d1):
            self.Warn('Invalid data')
            return None
        #d1[:ts1.VirtualAddress] = '\x00'* ts1.VirtualAddress
        #d1[ts1.VirtualAddress + ts1.SizeOfRawData: len(d1)] = '\x00'* (len(d1) - (ts1.VirtualAddress + ts1.SizeOfRawData))
        for dd in ddList1:
            d1[dd[0]:dd[0]+dd[1]] = '\x00' * dd[1]
        td1 = d1[ts1.VirtualAddress:ts1.VirtualAddress+ts1.SizeOfRawData]
        if td1 == '\x00' * len(td1):
            self.Warn('!!!section filled with all zeros. virtual address: {0}!!!'.format(ts1.VirtualAddress))
            return None
        return str(td1)

    @classmethod
    def GetDataDirectoriesInTextSection2(cls, ohdd2, ts2):
        ddList = []
        for index, dd in enumerate(ohdd2):
            if ts2.VirtualAddress <= dd.VirtualAddress < (ts2.VirtualAddress + ts2.SizeOfRawData):
                dirOff = dd.VirtualAddress - ts2.VirtualAddress + ts2.PointerToRawData
                ddList.append((dirOff, dd.Size))
        return ddList

    @classmethod
    def GetTextSectionData2(cls, d2, ddList2, ts2):
        if ts2.PointerToRawData >= len(d2):
            logging.error('Invalid data')
            return None
        if ts2.PointerToRawData + ts2.SizeOfRawData >= len(d2):
            logging.error('Invalid data')
            return None
        #d2[:ts2.PointerToRawData] = '\x00'* ts2.PointerToRawData
        #d2[ts2.PointerToRawData + ts2.SizeOfRawData: len(d2)] = '\x00'* (len(d2) - (ts2.PointerToRawData + ts2.SizeOfRawData))
        for dd in ddList2:
            d2[dd[0]:dd[0]+dd[1]] = '\x00' * dd[1]
        td2 = d2[ts2.PointerToRawData:ts2.PointerToRawData+ts2.SizeOfRawData]
        return str(td2)

    IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
    def CompareTextSectionWithRelocationInPython(self, td1, td2, ts2, ohdd2, ddList2, filePe):
        with UpdateCounterForScope('CompareTextSectionWithRelocation'):
            if ohdd2[self.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress:
                filePe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])
                filePe.relocate_image(long(self.DllBase))
                d3 = bytearray(filePe.__data__)
                td3 = self.GetTextSectionData2(d3, ddList2, ts2)
                if td3:
                    if td1 == td3:
                        self.MatchedAfterTextRelocation += 1
                        logging.info('.text section matches after relocation')
                        return True
                    self.DumpToFile(td3, self.File3DumpPath)
            self.DumpToFile(td1, self.File1DumpPath)
            self.DumpToFile(td2, self.File2DumpPath)
            return False

    def CompareTextSectionWithRelocationInCpp(self):
        with UpdateCounterForScope('CompareTextSectionWithRelocation'):
            return self.Validator.CompareTextSections()

    def _CompareTextSection(self, loadedPe, filePe):
        if hasattr(loadedPe, 'sections') != hasattr(filePe, 'sections'):
            self.Warn('!!!sections header does not match!!!')
            return False
        if not hasattr(loadedPe, 'sections'):
            return True
        ts1 = (sec for sec in loadedPe.sections if sec.Name.startswith('.text')).next()
        ohdd1 = loadedPe.OPTIONAL_HEADER.DATA_DIRECTORY
        d1 = bytearray(loadedPe.__data__)

        ts2 = (sec for sec in filePe.sections if sec.Name.startswith('.text')).next()
        ohdd2 = filePe.OPTIONAL_HEADER.DATA_DIRECTORY
        d2 = bytearray(filePe.__data__)

        ddList1 = self.GetDataDirectoriesInTextSection1(ohdd1, ts1)
        ddList2 = self.GetDataDirectoriesInTextSection2(ohdd2, ts2)

        td1 = self.GetTextSectionData1(d1, ddList1, ts1)
        if not td1:
            logging.info('no .text section inside loadedPe')
            return False
        td2 = self.GetTextSectionData2(d2, ddList2, ts2)
        if not td2:
            logging.info('no .text section inside filePe')
            return False
        if td1 == td2:
            logging.info('.text section match')
            return True
        else:
            if self.UseCpp:
                return self.CompareTextSectionWithRelocationInCpp()
            else:
                return self.CompareTextSectionWithRelocationInPython(td1, td2, ts2, ohdd2, ddList2, filePe)

    def CompareTextSection(self, loadedPe, filePe):
        with UpdateCounterForScope('CompareTextSection'):
            match = self._CompareTextSection(loadedPe, filePe)
            if match:
                logging.info('.text section match')
            else:
                self.TextSectionMismatched += 1
                self.Warn('!!!Text section data does NOT match even after relocation!!!')
            return match

    def ComparePe(self, loadedPe, filePe):
        if not self.HeadersReconstructed:
            if not self.CompareDosHeader(loadedPe, filePe):
                return False
            if not self.CompareNtHeader(loadedPe, filePe):
                return False
            if not self.CompareFileHeader(loadedPe, filePe):
                return False
            if not self.CompareOptionalHeader(loadedPe, filePe):
                return False
            if not self.CompareSectionHeaders(loadedPe,filePe):
                return False
            self.UseCpp = True
            if not self.CompareDataDirectories(loadedPe, filePe):
                return False
        if not self.CompareTextSection(loadedPe, filePe):
            return False
        self.Matched += 1
        return True

    def GetFilePe(self, exePath):
        with UpdateCounterForScope('GetFilePe'):
            filePe = None
            if os.path.exists(exePath):
                filePe = LruCache.get(exePath)
                if filePe:
                    logging.info("found in cache filePe for {0}".format(exePath))
                else:
                    filePe = pefile.PE(name=exePath, fast_load=True)
                    LruCache.set(exePath, filePe)
            else:
                self.Warn('!!!{0} found running but no file on disk!!!'.format(exePath))
                self.FilesNotFound += 1
            self.ExePath = exePath
            self.FilePe = filePe
            return filePe

    def ChangePointerToRawDataWithVirtualAddress(self):
        for section in self.LoadedPe.sections:
            section.PointerToRawData = section.VirtualAddress

    def GetLoadedPe(self, memoryData):
        with UpdateCounterForScope('GetLoadedPe'):
            assert self.FilePe
            self.LoadedPe = None
            self.HeadersReconstructed = False
            try:
                self.LoadedPe = pefile.PE(data=memoryData, fast_load=True)
                return self.LoadedPe
            except pefile.PEFormatError, e:
                self.Warn('Failed loading from memory: {0} with error: {1}'.format(self.ExePath, e))
            # try:
            #     numberOfSections = self.FilePe.FILE_HEADER.NumberOfSections
            #     lengthToCopy = self.FilePe.sections[numberOfSections -1].get_file_offset()
            #     memoryData[:lengthToCopy] = self.FilePe.__data__[:lengthToCopy]
            #     self.LoadedPe = pefile.PE(data=memoryData, fast_load=True)
            #     self.HeadersReconstructed = True
            #     return self.LoadedPe
            # except pefile.PEFormatError, e:
            #     self.Warn('Still failed loading after header reconstruction with error: {0}'.format(e))
            return self.LoadedPe

    def CompareExe(self, memoryData, exePath):
        with UpdateCounterForScope('pefile'):
            with self.ExceptionHandler('Failed comparing {0}'.format(exePath)):
                if self.GetFilePe(exePath) and self.GetLoadedPe(memoryData):
                    self.ComparePe(self.LoadedPe, self.FilePe)

    def BuildLoadedModuleAddressesFromVol(self, mods):
        self.Mods = {}
        for mod in mods:
            startAddress = long(mod.DllBase)
            endAddress = long(startAddress + mod.SizeOfImage)
            name = str(mod.BaseDllName).lower()
            if not self.Mods.get(name):
                self.Mods[name] = []
            self.Mods[name].append({
                'BaseDllName' : str(name),
                'FullDllName' : str(mod.FullDllName).lower(),
                'StartAddr' : startAddress,
                'EndAddr' : endAddress,
                'SizeOfImage' : long(mod.SizeOfImage)
            })
        self.Ntdll = self.Mods['ntdll.dll']
        self.Validator = AdMemoryValidatorClass()
        self.Validator.SetLoadedModules(self.Mods)

    def BuildLoadedModuleAddressesFromWinAppDbg(self, mods):
        self.Mods = mods
        self.Ntdll = self.Mods['ntdll.dll']
        self.Validator = AdMemoryValidatorClass()
        self.Validator.SetLoadedModules(mods)

    def InitializeModuleInfoFromVol(self, mod):
        logging.info("-------")
        self.DllBase = long(mod.DllBase)
        self.SizeOfImage = long(mod.SizeOfImage)
        self.BaseDllName = str(mod.BaseDllName).lower()
        dllPath = str(mod.FullDllName).lower()
        self.FullDllPath = ExpandPath(dllPath).lower()
        self.InitializeDumpPaths(self.BaseDllName)
        self.Message ="ImageName:{0} StartAddr:{1} EndAddr:{2} BaseDllName:{3} dllPath:{4} FullDllPath:{5}".format(
            self.ImageName, hex(self.DllBase), hex(self.DllBase + self.SizeOfImage), self.BaseDllName, dllPath, self.FullDllPath)
        logging.info(self.Message)
        mod = {
            'BaseDllName' : self.BaseDllName.lower(),
            'FullDllName' : self.FullDllPath.lower(),
            'StartAddr' : self.DllBase,
            'EndAddr' : self.DllBase + self.SizeOfImage,
            'SizeOfImage' : self.SizeOfImage
        }
        self.Validator.SetCurrentModuleInfo(mod)

    def InitializeModuleInfoFromWinAppDbg(self, mod):
        logging.info("-------")
        self.DllBase = long(mod['StartAddr'])
        self.SizeOfImage = long(mod['SizeOfImage'])
        self.BaseDllName = mod['BaseDllName']
        self.FullDllPath = mod['FullDllName']
        self.InitializeDumpPaths(self.BaseDllName)
        self.Message ="ImageName:{0} StartAddr:{1} EndAddr:{2} BaseDllName:{3} FullDllPath:{4}".format(
            self.ImageName, hex(self.DllBase), hex(self.DllBase + self.SizeOfImage), self.BaseDllName, self.FullDllPath)
        logging.info(self.Message)
        mod = {
            'BaseDllName' : self.BaseDllName.lower(),
            'FullDllName' : self.FullDllPath.lower(),
            'StartAddr' : self.DllBase,
            'EndAddr' : self.DllBase + self.SizeOfImage,
            'SizeOfImage' : self.SizeOfImage
        }
        self.Validator.SetCurrentModuleInfo(mod)
