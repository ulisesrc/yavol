__author__ = 'Jaroslav Brtan'

#--------------------------------------------------------------------------------
#TODO:
#
# [APP]
# !!! osetrit situaciu ked je profil nastaveny na imageinfo
# -> query db for result of worker thread!!!
# - output of modules to sqlite
# --> some modules needs additional parameters like pid
# https://github.com/JamesHabben/evolve/blob/master/evolve.py;
# - add dialog window for modules that need additional parameters (printkey,...)
# - add ldrmodules to the malware section
#   https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
# - if an image session is open, force user to close previous session before opening
#   a new image file (show dialog if current session should be closed/saved...)
# - add search dialog (ctrl+f search on active tab)
# - rules viewer/editor
# - do not open redundant tabs (like two similar pslists),
#   just change the active tcd ~`ab to the one requested
# - add possibility to store/restore analysis sessions
#   => store into a local db (sqlite,...)
# - settings.yalm for app setting
#   => where sigs, plugins are located
#   => remember last opened folder
#   => root window geometry
# - Use tkintertable for output of the volatility
#   data will be put into tables, sortable
#
# [YARA]
# - add a test rule for vawtrack
# - scan only:
#   kernel/user/pid
# - scan with:
#   all sigs/only selected/family
#
# [VOLATILITY]
# - plugin similar to malfind that will look for known bad habits
#   like process with known name running from unusual location
#   processes running from temp
#   injected processes
#--------------------------------------------------------------------------------




import sys
from PyQt4.QtGui import QApplication, QIcon
import MainWindow
import resources



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

