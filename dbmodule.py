import sqlite3 as lite
from collections import OrderedDict

class sqlitequery():

    def __init__(self, moduleName):
        self.con = None
        self.pathToDbFile = None # will be given when called
        if moduleName == 'pslist':
            self.moduleName = 'PSList'
        elif moduleName == 'psxview':
            self.moduleName = 'PsXview'
        elif moduleName == 'psscan':
            self.moduleName = 'PSScan'
        elif moduleName == 'netscan':
            self.moduleName = 'Netscan'
        elif moduleName == 'dlllist':
            self.moduleName = 'DllList'
        elif moduleName == 'handles':
            self.moduleName = 'Handles'
        elif moduleName == 'getsids':
            self.moduleName = 'GetSIDs'
        elif moduleName == 'privs':
            self.moduleName = 'Privs'
        elif moduleName == 'verinfo':
            self.moduleName = 'VerInfo'
        elif moduleName == 'malfind':
            self.moduleName = 'Malfind'
        elif moduleName == 'svcscan':
            self.moduleName = 'SvcScan'
        elif moduleName == 'yarascan':
            self.moduleName = 'YaraScan'
        else:
            self.moduleName = moduleName


    def getData(self):
            try:
                con = lite.connect('/home/yary/git/yavol_qt/output.sqlite')
                cur = con.cursor()
                cur.execute('SELECT * FROM ' + self.moduleName)
                names = list(map(lambda x: x[0], cur.description))

                data = OrderedDict()

                for index1, element in enumerate(names):
                    data[names[index1]] = []

                all_rows = cur.fetchall()

                for row in all_rows:
                    for y, name in enumerate(names):
                        data[name].append(row[y])

                if 'id' in data:
                    del data['id']
                if 'rowparent' in data:
                    del data['rowparent']

            except lite.Error, e:

                print "Error %s:" % e.args[0]
                pass

            finally:

                if con:
                    con.close()
            return data
