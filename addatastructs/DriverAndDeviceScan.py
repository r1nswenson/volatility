#!/usr/bin/env python

from rekall import session
from rekall.plugins.windows.common import PoolScanner

__author__ = 'nallred'

class PoolScanDriverAndDevice(PoolScanner):
    # modelled after PoolScanDriver class in rekall.plugins.windows.filescan
    """ Scan pool for driver or device object. """
    def __init__(self, **kwargs):
        super(PoolScanDriverAndDevice,self).__init__(**kwargs)
        self.checks = [
            ('MultiPoolTagCheck', dict(tags=[self.profile.get_constant('DRIVER_POOLTAG'), 'Dev\xE9', 'Devi'])),
            ('CheckPoolSize', dict(condition=lambda x: x > self.profile.get_obj_size('_DRIVER_OBJECT') or x > self.profile.get_obj_size('_DEVICE_OBJECT'))),
            ('CheckPoolType', dict(paged=True, non_paged=True, free=True)),
            ('CheckPoolIndex', dict(value=0))
        ]

def scan_for_drivers_and_devices(session):
    """ Returns lists of DRIVER_OBJECTs and DEVICE_OBJECTs (tupled with their names)
    (It's more efficient to search for drivers and devices together.) """
    profile = session.profile
    kas = session.kernel_address_space
    pas = session.physical_address_space
    scanner = PoolScanDriverAndDevice(session=session,profile=profile,address_space=pas)

    drivers = []
    devices = []
    for pool_obj in scanner.scan():
        object_obj = pool_obj.GetObject()
        if object_obj is None or not object_obj.get_object_type():
            continue
        objtype = object_obj.get_object_type()
        if objtype == 'Driver':
            name = object_obj.NameInfo.Name.v(vm=kas)
            if name is None: name = ''
            driver_object = profile._DRIVER_OBJECT(object_obj.obj_end, vm=pas)
            drivers.append( (name,driver_object) )
        elif objtype == 'Device':
            name = object_obj.NameInfo.Name.v(vm=kas)
            if name is None: name = ''
            device_obj = profile._DEVICE_OBJECT(object_obj.obj_end, vm=pas)
            devices.append( (name,device_obj) )

    return drivers, devices

