

__author__ = 'jhaddock'

import volatility.debug as debug
import addatastructs.process_pb2 as datastructs
from adplugins import adsockets as adsockets
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32.tasks as tasks
import addatastructs.adutils as adutils
import adcommon
from addatastructs.proto2xml import *
import adplugins.adyarascan as adyarascan
import volatility.plugins.kdbgscan as kdbgscan
import sys
import os

BLANK_MD5 = '0'*16
BLANK_SHA1 = '0'*20
_MMVAD_SHORT_TAGS = ['VadS', 'VadF']
PAGE_SIZE = 12


def _is_valid_service_table_address(address, memory_model='32bit'):
    """
    Validates address as a possible service table descriptor
    :param address: An address to check for possible service table descriptor
    :param memory_model: "32bit" for 32-bit addresses and "64bit" for 64-bit addresses
    :return: True if address is valid
             False if address is bogus
    """
    if memory_model == '64bit':
        return address >= 0x8000000000000000
    else:
        return address >= 0x80000000


def calculate_image_size(process):
    """
    Calculates the image size of process
    :param process: An _EPROCESS who's image size needs to be determined
    :return: The size of the image or 0 if calculation fails
    """
    try:
        process_as = process.get_process_address_space()
        image_base = process.Peb.ImageBaseAddress
        profile = process.obj_vm.profile

        idh = obj.Object('_IMAGE_DOS_HEADER', offset=image_base, vm=process_as)
        ifh = obj.Object('_IMAGE_FILE_HEADER', offset=image_base+idh.e_lfanew + 4, vm=process_as)

        ish = []
        curr = image_base +\
            idh.e_lfanew +\
            4 +\
            profile.get_obj_size('_IMAGE_FILE_HEADER') +\
            ifh.SizeOfOptionalHeader
        image_section_header_sz = profile.get_obj_size('_IMAGE_SECTION_HEADER')
        for i in range(ifh.NumberOfSections):
            ish.append(obj.Object('_IMAGE_SECTION_HEADER', offset=curr, vm=process_as))
            curr += image_section_header_sz

        lowest = reduce(lambda x,y: x if x.PointerToRawData < y.PointerToRawData and x.SizeOfRawData!=0 else y, ish, ish[0])
        return sum(map(lambda x: x.SizeOfRawData,ish),lowest.PointerToRawData)
    except:
        return 0


def flip_slashes(path):
    return str(path).replace('\\', '/')


def remove_device_name(file_name_with_device):
    return file_name_with_device


def get_handle_name(handle):
    name = ''
    object_type = handle.get_object_type()
    if object_type == 'File':
        file_obj = handle.dereference_as('_FILE_OBJECT')
        name = flip_slashes(remove_device_name(file_obj.file_name_with_device()))
    elif object_type == 'Key':
        key_obj = handle.dereference_as('_CM_KEY_BODY')
        name = '/REGISTRY/{0}'.format(flip_slashes(key_obj.full_key_name()))
    elif object_type == 'Process':
        proc_obj = handle.dereference_as('_EPROCESS')
        name = '{0} ({1})'.format(proc_obj.ImageFileName, proc_obj.UniqueProcessId)
    elif object_type == 'Thread':
        thrd_obj = handle.dereference_as('_ETHREAD')
        name = '{0}'.format(thrd_obj.Cid.UniqueThread)
    elif handle.NameInfo.Name == None:
        name = '<UNNAMED>'
    else:
        name = str(handle.NameInfo.Name)

    return adutils.SmartUnicode(name)


class ADProcesses:
    """Get a list of processes and extract useful information from them"""


    def get_full_name(self, name, path):
        name = adutils.SmartUnicode(name)
        length = len(name)
        if length >= 14:
            path = adutils.SmartUnicode(path)
            last_slash = path.rfind('\\')
            path = path[last_slash + 1:]
            if len(path) > length and name == path[:length]:
                name = path
        return name


    def execute(self,options,config,yarapath):
        addr_space = utils.load_as(config)

        if not os.path.isfile("kdcopydatablock.txt"):
            if (addr_space.profile.metadata.get("os") == "windows" and addr_space.profile.metadata.get("memory_model") == "64bit" and addr_space.profile.metadata.get("major") >= 6 and addr_space.profile.metadata.get("minor") >= 2):
                kdbg = tasks.get_kdbg(addr_space)
                fout = open('kdcopydatablock.txt', 'w')
                kdblockaddr = '{0:#x}'.format(kdbg.KdCopyDataBlock)
                fout.write(kdblockaddr)
                fout.close()
                sys.argv.append("--kdbg")
                sys.argv.append(kdblockaddr)
        
        processList = tasks.pslist(addr_space)

        if adutils.getConfigValue(options,'sockets') == True:
            getSocketsDelegate = adsockets.getSocketsFactory(addr_space.profile)
            sockets = getSocketsDelegate(config,addr_space)

        if adutils.getConfigValue(options,'yarascan') == True:
            getYaraDelegate = adyarascan.getYaraFactory(addr_space.profile)
            config.update('YARA_RULES_DIRECTORY',yarapath)
            compiledrules = getYaraDelegate(config).compile_rules()

        list_head_offset = None
        has_service_table = False

        process_obj_list = datastructs.rootType()

        for processIndex, eprocess in enumerate(processList):
            config.process_id = eprocess.UniqueProcessId
            config.dtb = eprocess.Pcb.DirectoryTableBase

            all_mods = list(eprocess.get_load_modules())

            # get Token for Privileges
            token = eprocess.Token.dereference_as('_TOKEN')
            if hasattr(token.Privileges, 'Present'):
                privileges = token.Privileges.Present
            else:
                # Current memory analysis erroneously points
                # to token.ModifiedId for privileges for XP
                # The line below will match what the current memory analysis collects:
                # privileges = token.ModifiedId.LowPart
                # I don't think this is correct, either.
                luid = token.Privileges.dereference_as('_LUID_AND_ATTRIBUTES')
                privileges = luid.Luid.LowPart
            
            validName = "Unknown"    
            if eprocess.ImageFileName:
                validName = eprocess.ImageFileName
            name = self.get_full_name(name=validName, path=eprocess.Peb.ProcessParameters.ImagePathName or '')
            try:
                process_obj = process_obj_list.Process.add(
                    resultitemtype=18,
                    Name=name,
                    Path=adutils.SmartUnicode(eprocess.Peb.ProcessParameters.ImagePathName or ""),
                    StartTime=adutils.SmartUnicode(eprocess.CreateTime or ""),
                    WorkingDir=adutils.SmartUnicode(eprocess.Peb.ProcessParameters.CurrentDirectory.DosPath or ""),
                    CommandLine=adutils.SmartUnicode(eprocess.Peb.ProcessParameters.CommandLine or ""),
                    LinkTime=0,
                    Subsystem=long(eprocess.Peb.ImageSubsystem),
                    Imagebase=long(eprocess.Peb.ImageBaseAddress),
                    Characteristics=0,
                    Checksum=0,
                    KernelTime=long(eprocess.Pcb.KernelTime),
                    UserTime=long(eprocess.Pcb.UserTime),
                    Privileges=long(privileges),
                    PID=int(eprocess.UniqueProcessId),
                    ParentPID=int(eprocess.InheritedFromUniqueProcessId),
                    User='',
                    Group='',
                    MD5=BLANK_MD5,
                    SHA1=BLANK_SHA1,
                    FuzzySize=0,
                    Fuzzy='',
                    Fuzzy2X='',
                    KFFStatus=0,
                    FromMemory='',
                    EffectiveUser='',
                    EffectiveGroup='',
                    Size=calculate_image_size(eprocess),
                    EProcBlockLoc=long(eprocess.obj_vm.vtop(eprocess.obj_offset)) or 0,
                    WindowTitle=adutils.SmartUnicode(eprocess.Peb.ProcessParameters.WindowTitle or "")
                )
            except:
                debug.info('Caught error in adding process, continuing')
                continue

            kthread = eprocess.Pcb.ThreadListHead.Flink.dereference_as('_KTHREAD')
            list_head_offset = kthread.ThreadListEntry.obj_offset - kthread.obj_offset
            kthread = obj.Object('_KTHREAD', offset=eprocess.Pcb.ThreadListHead.Flink - list_head_offset, vm=eprocess.obj_vm)
            if hasattr(kthread, 'ServiceTable'):
                SDTs = set()
                for i in range(eprocess.ActiveThreads):
                    if _is_valid_service_table_address(address=kthread.ServiceTable, memory_model=eprocess.obj_vm.profile.metadata.get('memory_model', '32bit')):
                        SDTs.add(long(kthread.ServiceTable))
                    kthread = obj.Object('_KTHREAD', offset=kthread.ThreadListEntry.Flink - list_head_offset, vm=eprocess.obj_vm)
                for sdt in SDTs:
                    process_obj.SDT.append(sdt)

            if adutils.getConfigValue(options,'processdlls') == True:
                for moduleIndex, module in enumerate(all_mods):
                    baseName = "Unknown"
                    if module.BaseDllName:
                        baseName = module.BaseDllName
                    dll_obj = process_obj.Loaded_DLL_List.DLL.add(
                        Name=adutils.SmartUnicode(baseName or ''),
                        Description='',
                        Path=adutils.SmartUnicode(module.FullDllName or ''),
                        Version='',
                        MD5=BLANK_MD5,
                        SHA1=BLANK_SHA1,
                        FuzzySize=0,
                        Fuzzy='',
                        Fuzzy2X='',
                        CreateTime=u"0000-00-00 00:00:00", #adutils.SmartUnicode(module.TimeDateStamp),
                        KFFStatus=0,
                        PID=int(eprocess.UniqueProcessId),
                        baseAddress=long(module.DllBase),
                        ImageSize=long(module.SizeOfImage),
                        ProcessName=name,
                        FromMemory=''
                    )
            if adutils.getConfigValue(options,'sockets') == True:
                pid = int(eprocess.UniqueProcessId)
                if pid in sockets:
                    process_obj.Open_Sockets_List.CopyFrom(sockets[pid])

            if adutils.getConfigValue(options,'handles') == True:
                if eprocess.ObjectTable.HandleTableList:
                    for handle in eprocess.ObjectTable.handles():
                        if not handle.is_valid():
                            continue
                        handle_obj = process_obj.Open_Handles_List.OpenHandle.add(
                            ID=long(handle.HandleValue),
                            Type=adutils.SmartUnicode(handle.get_object_type()),
                            Path=get_handle_name(handle),
                            AccessMask=int(handle.GrantedAccess),
                            Name='',
                            PID=int(eprocess.UniqueProcessId),
                            PointerCount=long(handle.PointerCount),
                            ObjectAddress=long(handle.obj_offset),
                            FromMemory='',
                            Owner='',
                            Group='',
                            Permissions=''
                        )
            if adutils.getConfigValue(options,'vad') == True:
                for vad in eprocess.VadRoot.traverse():
                    longflags = 0
                    if hasattr(vad, 'u'):
                        longflags = long(vad.u.LongFlags)
                    elif hasattr(vad, 'Core'):
                        longflags = long(vad.Core.u.LongFlags)
                    vad_obj = process_obj.Vad_List.Vad.add(
                        Protection=int(vad.VadFlags.Protection),
                        StartVpn=long(vad.Start >> PAGE_SIZE),
                        EndVpn=long(vad.End >> PAGE_SIZE),
                        Address=long(vad.obj_offset),
                        Flags=longflags,
                        Mapped=u'False',
                        ProcessName=process_obj.Name,
                        PID=process_obj.PID,
                        FromMemory='')
                    if not vad.Tag in _MMVAD_SHORT_TAGS:
                        if vad.FileObject and vad.FileObject.FileName:
                            name = str(vad.FileObject.FileName)
                            if len(name) > 0 and name[0] == '\\':
                                vad_obj.Filename = adutils.SmartUnicode(name)
                                vad_obj.Mapped = u'True'
                            else:
                                print name

            if adutils.getConfigValue(options,'yarascan') == True:
                pid = int(eprocess.UniqueProcessId)
                config.update('pid',str(pid))
                yara = getYaraDelegate(config).calculateonvad(compiledrules, eprocess)
                try:
                    for hit in yara:
                        process_obj.YaraHits.YaraHit.add(
                            id='',
                            Name=hit[2].rule,
                            Category='')
                except:
                    debug.info('Caught error in adding yarahit, continuing')

        file = open(config.OUTPUT_PATH + "processes.xml", "w")
        #file.write(process_obj_list.SerializeToString())
        file.write(proto2xml(process_obj_list,indent=0))
