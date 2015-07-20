'''
Yavol - GUI for volatility framework and yara scanner
Copyright (C) 2015  Jaroslav Brtan

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import sqlite3 as lite
from collections import OrderedDict


class sqlitequery():

    def __init__(self, moduleName, database_path):
        self.con = None
        self.pathToDbFile = None # will be given when called
        self.db_path = database_path
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
                con = lite.connect(self.db_path)
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

    def storeImageData(self, imgName, imgSize, imgPath, time):
        try:
            status = False
            con = lite.connect(self.db_path)
            cur = con.cursor()

            #check if the file table exists
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='AnalysisFile'")
            row = cur.fetchone()
            if row:
                print row
            else:
                cur.execute('''CREATE TABLE AnalysisFile(
                            id  INTEGER,
                            imgName TEXT,
                            imgSize INTEGER,
                            imgPath TEXT,
                            imgLastProfile TEXT,
                            dbCreated INTEGER,
                            dbLastOpened INTEGER)''')
                cur.execute('INSERT INTO AnalysisFile(id, imgName, imgSize, imgPath, imgLastProfile, dbCreated,\
                            dbLastOpened) VALUES (?,?,?,?,?,?,?)', (1, imgName, imgSize, imgPath, '', time, time,))
                con.commit()
                status = True

            #cur.execute('INSERT INTO FROM ' + self.moduleName)
        except lite.Error, e:

            print "Error %s:" % e.args[0]

        finally:

            if con:
                con.close()
            return status

    def updateProfileInfo(self, imgLastProfile):

        try:
            con = lite.connect(self.db_path)
            cur = con.cursor()

            #check if the file table exists
            cur.execute("UPDATE AnalysisFile SET imgLastProfile = ? WHERE id=1", (imgLastProfile,))
            con.commit()
        except lite.Error, e:

            print "Error %s:" % e.args[0]
            pass

        finally:

            if con:
                con.close()

    def getProfileInfo(self):
        try:
            print(self.db_path)
            con = lite.connect(self.db_path)
            cur = con.cursor()

            #check if the file table exists
            cur.execute("SELECT * FROM AnalysisFile WHERE id=1")
            row = cur.fetchone()
            if row:
                return row
            else:
                return False

        except lite.Error, e:

            print "Error %s:" % e.args[0]
            pass

        finally:

            if con:
                con.close()

    def checkForTable(self):
        try:
            status = False
            con = lite.connect(self.db_path)
            cur = con.cursor()

            #check if the file table exists
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (self.moduleName,))
            row = cur.fetchone()
            if row:
                status = True
            else:
                status = False
        except lite.Error, e:

            print "Error %s:" % e.args[0]

        finally:

            if con:
                con.close()
            return status

    def dropYaraScanTable(self, tableName):

        try:
            con = lite.connect(self.db_path)
            cur = con.cursor()

            #check if the file table exists
            cur.execute("DROP TABLE IF EXISTS YaraScan")
            con.commit()

        except lite.Error, e:

            print "Error %s:" % e.args[0]

        finally:

            if con:
                con.close()

