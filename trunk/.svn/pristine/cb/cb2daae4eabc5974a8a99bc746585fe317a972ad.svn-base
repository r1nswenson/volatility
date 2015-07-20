
import volatility.plugins.common as common
import volatility.poolscan as poolscan
from volatility.plugins.filescan import PoolScanDriver
import volatility.plugins.modules as modules
import volatility.win32.modules as win32modules
import volatility.obj as obj
import volatility.utils as utils
import addatastructs.device_pb2 as devicedatastructs
import addatastructs.driver_pb2 as driverdatastructs
import logging
from bisect import bisect_right
import volatility.addrspace as addrspace
from addatastructs.proto2xml import *
from adplugins.adcommon import find_module

BLANK_MD5 = '0'*16
BLANK_SHA1 = '0'*20

class PoolScanDevice(poolscan.PoolScanner):
    """Base Pool scanner for device objects"""

    def __init__(self, address_space):
        poolscan.PoolScanner.__init__(self, address_space)

        self.struct_name = "_DEVICE_OBJECT"
        self.object_type = "Device"
        # due to the placement of the driver extension, we
        # use the top down approach instead of bottom-up.
        self.use_top_down = True
        size = 0x150 # self.address_space.profile.get_obj_size("_DEVICE_OBJECT")

        self.checks = [
            ('CheckPoolSize', dict(condition = lambda x: x >= size)),
            ('CheckPoolType', dict(paged=False, non_paged=True, free=True)),
            ('CheckPoolIndex', dict(value = 0)),
            ]

class PoolScanDevice_Deve9(PoolScanDevice):
    """Pool scanner for device objects Dev\\xe9"""

    def __init__(self, address_space):
        PoolScanDevice.__init__(self, address_space)
        self.pooltag = 'Dev\xe9' #obj.VolMagic(address_space).DevicePoolTag.v()

class PoolScanDevice_Devi(PoolScanDevice):
    """Pool scanner for device objects - pool tag Devi"""

    def __init__(self, address_space):
        PoolScanDevice.__init__(self, address_space)
        self.pooltag = 'Devi' #obj.VolMagic(address_space).DevicePoolTag.v()


class DriverDeviceScan:
    """Pool scanner for driver objects"""
    scanners = [PoolScanDriver, PoolScanDevice_Deve9, PoolScanDevice_Devi]

    def scan_results(self, addr_space):
        multiscan = poolscan.MultiScanInterface(addr_space = addr_space, scanners = self.scanners)
        return multiscan.scan()

    def doDrivers(self, config, drivers, devices):
        print "Doing DoDrivers"

        driverObjList = driverdatastructs.rootType()

        for driver_name, driver_object in drivers:
            driverObj = driverObjList.Driver.add(resultitemtype=5) #ResultDriverItem

            baseaddress = driver_object.DriverStart.v()
            module = find_module(config, baseaddress)
            driverObj.ImagePath=module.FullDllName.v() if module and module.FullDllName else ''

            driverObj.BaseAddress=baseaddress
            driverObj.Type=driver_object.Type.v()
            driverObj.DeviceObj_Location=driver_object.obj_native_vm.vtop(driver_object.DeviceObject.v()) or 0
            driverObj.Driver_Init=driver_object.DriverInit.v()
            driverObj.Driver_StartIO=driver_object.DriverStartIo.v()
            driverObj.Driver_Unload=driver_object.DriverUnload.v()
            driverObj.StartTime='0000-00-00 00:00:00' # currently we don't have a reliable source for this info
            driverObj.Dependencies='' # this is a linux thing
            driverObj.Size=driver_object.DriverSize.v()
            driverObj.Instances=0 # this is a linux thing
            driverObj.Name=driver_object.DriverName.v()
            driverObj.StartedAs=''
            driverObj.State=4 #running
            driverObj.RealState=-1 #unknown
            driverObj.StartMode=-1 #unknown
            driverObj.RealStartMode=-1 #unknown
            driverObj.RealType=0 #unknown
            driverObj.Path=''
            driverObj.plist=''
            driverObj.MD5=BLANK_MD5
            driverObj.SHA1=BLANK_SHA1
            #Leave out FuzzyHash for now
            #FuzzySize =
            #Fuzzy =
            #Fuzzy2X =
            driverObj.KFFStatus=0 #I guess we don't do this
            driverObj.processid=0 #meaningless for drivers

            major_functions = driver_object.MajorFunction
            driverObj.IRP_MJ_CREATE=major_functions[0].v()
            driverObj.IRP_MJ_CREATE_NAMED_PIPE=major_functions[1].v()
            driverObj.IRP_MJ_CLOSE=major_functions[2].v()
            driverObj.IRP_MJ_READ=major_functions[3].v()
            driverObj.IRP_MJ_WRITE=major_functions[4].v()
            driverObj.IRP_MJ_QUERY_INFORMATION=major_functions[5].v()
            driverObj.IRP_MJ_SET_INFORMATION=major_functions[6].v()
            driverObj.IRP_MJ_QUERY_EA=major_functions[7].v()
            driverObj.IRP_MJ_SET_EA=major_functions[8].v()
            driverObj.IRP_MJ_FLUSH_BUFFERS=major_functions[9].v()
            driverObj.IRP_MJ_QUERY_VOLUME_INFORMATION=major_functions[10].v()
            driverObj.IRP_MJ_SET_VOLUME_INFORMATION=major_functions[11].v()
            driverObj.IRP_MJ_DIRECTORY_CONTROL=major_functions[12].v()
            driverObj.IRP_MJ_FILE_SYSTEM_CONTROL=major_functions[13].v()
            driverObj.IRP_MJ_DEVICE_CONTROL=major_functions[14].v()
            driverObj.IRP_MJ_INTERNAL_DEVICE_CONTROL=major_functions[15].v()
            driverObj.IRP_MJ_SHUTDOWN=major_functions[16].v()
            driverObj.IRP_MJ_LOCK_CONTROL=major_functions[17].v()
            driverObj.IRP_MJ_CLEANUP=major_functions[18].v()
            driverObj.IRP_MJ_CREATE_MAILSLOT=major_functions[19].v()
            driverObj.IRP_MJ_QUERY_SECURITY=major_functions[20].v()
            driverObj.IRP_MJ_SET_SECURITY=major_functions[21].v()
            driverObj.IRP_MJ_POWER=major_functions[22].v()
            driverObj.IRP_MJ_SYSTEM_CONTROL=major_functions[23].v()
            driverObj.IRP_MJ_DEVICE_CHANGE=major_functions[24].v()
            driverObj.IRP_MJ_QUERY_QUOTA=major_functions[25].v()
            driverObj.IRP_MJ_SET_QUOTA=major_functions[26].v()
            driverObj.IRP_MJ_PNP=major_functions[27].v()

            # Use DriverExtension struct to get some additional information
            try:
                driver_extension = driver_object.DriverExtension
                driverObj.ServiceKeyName=driver_extension.ServiceKeyName or '<UNAVAILABLE>'
                driverObj.DriverObj_Location=driver_object.obj_native_vm.vtop(driver_extension.DriverObject.v()) or 0

            except:
                # I guess we just won't have this data
                driverObj.ServiceKeyName='<UNAVAILABLE>'
                driverObj.DriverObj_Location=0

            #associated devices
            for device_name, device_object in devices:
                if device_object.obj_native_vm.vtop(device_object.DriverObject.v()) == driver_object.v():
                    deviceObj = driverObj.Driver_Device_List.Device.add(
                        Name=device_name,
                        DeviceObj_Location=device_object.v() or 0,
                        DriverObj_Location=device_object.obj_native_vm.vtop(device_object.DriverObject.v() or 0) or 0,
                        NextDeviceObj_Location=device_object.obj_native_vm.vtop(device_object.NextDevice.v() or 0) or 0,
                        AttachedDeviceObj_Location= device_object.obj_native_vm.vtop(device_object.AttachedDevice.v() or 0) or 0
                    )

        file = open(config.OUTPUT_PATH + "drivers.xml", "w")
        #file.write(driverObjList.SerializeToString())
        file.write(proto2xml(driverObjList,indent=0))
        logging.debug("Completed exporting the drivers on the system")

    def doDevices(self, config, devices):
        print "Doing DoDevices"
        deviceObjList = devicedatastructs.rootType()

        for device_name,device_object in devices:
            deviceObj = deviceObjList.Device.add(
                Name=device_name,
                DeviceObj_Location=device_object.v() or 0,
                DriverObj_Location=device_object.obj_native_vm.vtop(device_object.DriverObject.v() or 0) or 0,
                NextDeviceObj_Location=device_object.obj_native_vm.vtop(device_object.NextDevice.v() or 0) or 0,
                AttachedDeviceObj_Location=device_object.obj_native_vm.vtop(device_object.AttachedDevice.v() or 0) or 0
            )

        file = open(config.OUTPUT_PATH + "devices.xml", "w")
        #file.write(deviceObjList.SerializeToString())
        file.write(proto2xml(deviceObjList,indent=0))
        logging.debug("Completed exporting the deviceObjects on the system")

    #addr_space = utils.load_as(config)
    #addr_space = utils.load_as(self._config, astype='kernel')
    #addr_space = utils.load_as(self._config, astype='physical')
    def execute(self,config):
        addr_space = utils.load_as(config)
        drivers = []
        devices = []
        for d in self.scan_results(addr_space):
            if d.obj_type == '_DRIVER_OBJECT':
                drivers.append( (d.DriverName.v(),d) )
            else:
                device_header = obj.Object("_OBJECT_HEADER", offset = d.obj_offset -
                    d.obj_vm.profile.get_obj_offset("_OBJECT_HEADER", "Body"),
                    vm = d.obj_vm,
                    native_vm = d.obj_native_vm
                    )
                name = str(device_header.NameInfo.Name or '')
                devices.append( (name,d) )

        self.doDrivers(config,drivers,devices)
        self.doDevices(config, devices)



