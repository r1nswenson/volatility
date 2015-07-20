import logging
import sys
import os
import traceback
import json
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import adplugins.adkernelmodules as adkernelmodulesfactory
import adplugins.adprocesses as adprocessesfactory
import adplugins.addriversanddevices as addriveranddevicefactory
import adplugins.adsdts as adsdtfactory
import adplugins.adregistry as adregistryfactory
import addatastructs.adutils as utils
import adplugins.adkpcr as kpcr
from addatastructs.proto2xml import *
from admem.adprofilegenerator import ProfileGeneratorClass

from perf import CounterMonitorClass, UpdateCounterForScope

CounterMonitor = CounterMonitorClass('admemoryanalysis-perf.db')
CounterMonitor.Start()

def setupLogging(filePath, loggingLevel):
    try:
        os.remove(filePath)
    except OSError:
        pass
    logging.basicConfig(level=loggingLevel)

    logger = logging.getLogger('')
    logger.handlers = []

    loggingFormat = '%(asctime)s %(levelname)s:%(message)s'
    logFormatter = logging.Formatter(loggingFormat)

    fileLogger = logging.FileHandler(filePath)
    fileLogger.setFormatter(logFormatter)
    logger.addHandler(fileLogger)

    consoleLogger = logging.StreamHandler()
    consoleLogger.setFormatter(logFormatter)
    logger.addHandler(consoleLogger)

def main(argv=None):
    setupLogging("admemanalysis.log",logging.INFO)
    registry.PluginImporter()
    config = conf.ConfObject()
    config.add_option('OUTPUT-PATH', default=None,
                      help='Where to create output files',
                      action='store', type='str')
    config.process_id = None
    registry.register_global_options(config, commands.Command)
    registry.register_global_options(config, addrspace.BaseAddressSpace)

    if not os.path.isfile("inputdata.json"):
        raise NameError("Input file(inputdata.json) was not found")
    data = None

    with open("inputdata.json") as data_file:
        data = json.load(data_file)
    operations = data['operationdata']

    sys.argv.append("-f")
    sys.argv.append(data["filestreamtoanalyze"])
    sys.argv.append("--profile")
    profile = data["profiletypename"] or ProfileGeneratorClass().GetProfile()
    logging.info('profile detected is {0}'.format(profile))
    sys.argv.append(profile)

    output_path = data.get('outputpath') or ''
    yrd = data.get('yararulesdirectory') or ''

    config.parse_options(False)
    sys.argv.append("--output-path")
    sys.argv.append(output_path)

    if os.path.isfile("kdcopydatablock.txt"):
        with open("kdcopydatablock.txt") as kdfile:
            kddata = kdfile.readline()
            logging.debug('read from file %s', kddata)
            sys.argv.append("--kdbg")
            sys.argv.append(kddata)

    config.parse_options()

    if utils.getConfigValue(operations,'process') == True:
        adprocessesfactory.ADProcesses().execute(operations,config,yrd)

    if utils.getConfigValue(operations,'drivers') == True:
        addriveranddevicefactory.DriverDeviceScan().execute(config)

    if utils.getConfigValue(operations,'modules') == True:
        adkernelmodulesfactory.ADKernelModules().execute(config)

    if utils.getConfigValue(operations,'sdts')== True:
        adsdtfactory.ADSdtGenerator().execute(config)

    if utils.getConfigValue(operations,'idt') == True:
        processors = kpcr.doProcessors(config)
        f = open(config.OUTPUT_PATH + 'processors.xml','w')
        #f.write(processors.SerializeToString())
        f.write(proto2xml(processors,indent=0))

    if utils.getConfigValue(operations,'registry') == True:
        adregistryfactory.ADRegistryExtractor().execute(config)


if __name__ == '__main__':
    try:
        with UpdateCounterForScope('main'):
            main()
        CounterMonitor.Stop()
    except Exception, e:
        logging.exception(e)
    except SystemExit, e:
        pass
    CounterMonitor.Stop()
