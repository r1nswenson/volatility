__author__ = 'achigurala'
import volatility.plugins.registry.printkey as volregistry
import addatastructs.registry_pb2 as datastructs
import volatility.win32.rawreg as rawreg
import volatility.obj as obj
import addatastructs.adutils as utils
import volatility.utils as volutils
from addatastructs.proto2xml import *

class ADRegistryExtractor:


    def _get_raw_registry_data2(self,regvalue):
        tp, dat = rawreg.value_data(regvalue)
        if tp == 'REG_BINARY' or tp == 'REG_NONE':
            dat = "\n" + "\n".join(["{0:#010x}  {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in volutils.Hexdump(dat)])
        if tp in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_LINK']:
            dat = dat.encode("ascii", 'backslashreplace')
        if tp == 'REG_MULTI_SZ':
            for i in range(len(dat)):
                dat[i] = dat[i].encode("ascii", 'backslashreplace')
        return dat

    def _get_raw_registry_data(self,regvalue):
        ''' Get the raw data bytes from a registry value. (Derived from _CM_KEY_VALUE.DecodedData in registry.py) '''
        # When the data length is 0x80000000, the value is stored in the type
        # (as a REG_DWORD).
        if regvalue.DataLength == 0x80000000:
            return regvalue.Type.v()

        # If the high bit is set, the data is stored inline
        elif regvalue.DataLength & 0x80000000:
            return regvalue.obj_vm.read(regvalue.m("Data").obj_offset, regvalue.DataLength & 0x7FFFFFFF)

        elif regvalue.DataLength > 0x4000:
            return obj.NoneObject("Big data not supported.")
            # todo: add support for big data to Rekall, or change this when support has been added
        else:
            return regvalue.obj_vm.read(int(regvalue.m("Data")), regvalue.DataLength)
    def vol(self,k):
        return bool(k.obj_offset & 0x80000000)

    def voltext(self, key):
        return True if self.vol(key) else False

    def getregistrykeyobject(self,reg,key,regObjList):
        regKeyObject = regObjList.RegistryKey.add(resultitemtype=19)
        regKeyObject.Name=utils._utf8_encode(key.Name)
        path = reg
        lastSlash = reg.rfind("/")
        if lastSlash >= 0:
            path = "\\" + reg[:lastSlash].replace("/", "\\")
        regKeyObject.Path=utils._utf8_encode(path)
        regKeyObject.Volatile=self.voltext(key)
        regvalues = rawreg.values(key)
        if regvalues is not None and len(regvalues) > 0:
            values = regKeyObject.Values
            values.Count=len(regvalues)
            for value in regvalues:
                regKeyValue = values.RegistryValue.add(resultitemtype=21)
                regKeyValue.Name=utils._utf8_encode(value.Name)
                regKeyValue.Type=value.Type.v() or 0
                try:
                    regKeyValue.Value = self._get_raw_registry_data2(value)
                except Exception as e:
                    regKeyValue.Value = "EXCEPTION: " + str(e)

        return regKeyObject

    def LoadSubKeys(self,reg,key,regObjectList):
        for k in rawreg.subkeys(key):
            r = reg + '\\' + utils._utf8_encode(k.Name)
            self.getregistrykeyobject(r,k,regObjectList)
            self.LoadSubKeys(r,k,regObjectList)

    def execute(self,config):
        regObjList = datastructs.rootType()

        keys = volregistry.PrintKey(config).calculate()
        for reg, key in keys:
            self.getregistrykeyobject(reg,key,regObjList)
            self.LoadSubKeys(reg,key,regObjList)

        registryfile = open(config.OUTPUT_PATH + "registry.xml", "w")
        #registryfile.write(regObjList.SerializeToString())
        registryfile.write(proto2xml(regObjList,indent=0))