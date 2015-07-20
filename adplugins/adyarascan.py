__author__ = 'thospodarsky'
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.linux.linux_yarascan as linuxyara
import volatility.plugins.mac.mac_yarascan as macyara

def getYaraFactory(profile):
    if (profile.metadata.get("os") == "windows"):
        return malfind.YaraScan
    else:
        if (profile.metadata.get("os") == "linux"):
            return linuxyara.linux_yarascan
        else:
            return macyara.mac_yarascan
