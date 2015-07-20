import os

class Paths(object):
    @classmethod
    def GetDatabaseDirectory(self):
        if os.environ.get('ProgramData'):
            programDataDirectory = os.environ.get('ProgramData')
            databaseDirectory = os.path.join(programDataDirectory, 'counter-dbs')
        else:
            databaseDirectory = os.path.join(os.getcwd(), 'counter-dbs')
        if not os.path.exists(databaseDirectory):
            os.makedirs(databaseDirectory)
        return databaseDirectory

    @classmethod
    def GetDatabasePath(self, databaseName):
        return  os.path.join(Paths.GetDatabaseDirectory(), databaseName)
