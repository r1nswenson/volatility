__author__ = 'achigurala'
import volatility.plugins.malware.malfind as malfind
import addatastructs.processdatastructs as datastructs
class ADYaraScan:

    def execute(self,rulesdirectory,config):

        config.update('YARA_RULES_DIRECTORY',rulesdirectory)
        yaraHitsObj = processdatastructs.YaraHitsType.factory()
        for task, address, hit, _ in malfind.YaraScan(config).calculate():
            yarahitObj = datastructs.YaraHitsType.factory()
            yarahitObj.set_id(hit.namespace)
            yarahitObj.set_Name(hit.rule)
            yarahitObj.set_Category(category)
            yaraHitsObj.set_YaraHit(yarahitObj)
