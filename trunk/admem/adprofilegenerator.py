import sys
import platform

class ProfileGeneratorClass(object):
    def __init__(self):
        self.Version = sys.getwindowsversion()

    def _GetArch(self):
        self.Arch = 'x86'
        if platform.architecture()[0] == '64bit':
            self.Arch = 'x64'
        return self.Arch

    def _IsServer(self):
        VER_NT_WORKSTATION = 1
        return self.Version.product_type != VER_NT_WORKSTATION

    def _GetOsName(self):
        if self.Version.major == 5 and self.Version.minor == 1:
            self.Os = 'WinXP'
        elif self.Version.major == 5 and self.Version.minor == 2:
            self.Os = 'Win2003'
        elif self.Version.major == 6 and self.Version.minor == 0:
            if self._IsServer():
                self.Os = 'Win2008'
            else:
                self.Os = 'Vista'
        elif self.Version.major == 6 and self.Version.minor == 1:
            if self._IsServer():
                self.Os = 'Win2008R2'
            else:
                self.Os = 'Win7'
        elif self.Version.major == 6 and self.Version.minor == 2:
            if self._IsServer():
                self.Os = 'Win2012'
            else:
                self.Os = 'Win8'
        elif self.Version.major == 6 and self.Version.minor == 3:
            if self._IsServer():
                self.Os = 'Win2012R2'
            else:
                self.Os = 'Win8'
        else:
            self.Os = None
        return self.Os

    def _GetServicePack(self):
        self.Sp = 'SP' + str(self.Version.service_pack_major)
        return self.Sp

    def _GetOsInformation(self):
        return self._GetArch() and self._GetOsName() and self._GetServicePack()

    def GetProfile(self):
        if not self._GetOsInformation():
            return None
        return self.Os + self.Sp + self.Arch
