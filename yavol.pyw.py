'''
YaVol - GUI for volatility framework and yara scanner
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


import sys
from PyQt4.QtGui import QApplication, QIcon
import MainWindow


#--------------------------------------------------------------------------------
# TODO: indicate to the user that a module is still running (spinning wheel,...)
# TODO: clean the code of the volatility instance variable usage
# TODO: add a view option that will enable to switch visibility of the logdock window
# TODO: fix issue with the enumfunc module malfunction
# TODO: fix bug when more than one yara rule is used for scanning and at least one is with no hit (display it properly in treewindow)
# TODO: add dump dir to settings
# TODO: ctrl+F -> add support for quick search on tabs
#--------------------------------------------------------------------------------



def main():
    app = QApplication(sys.argv)
    app.setOrganizationName("redteam")
    app.setOrganizationDomain("redteam.sk")
    app.setApplicationName("yavol")
    app.setWindowIcon(QIcon(":/icon.png"))
    window = MainWindow.Window()
    window.show()
    app.exec_()


if __name__ == "__main__":
    main()

