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

import pprint


from PyQt4.QtCore import Qt, QSettings, QString
from PyQt4.QtGui import QDialog, QLabel, QVBoxLayout, QHBoxLayout, QGridLayout, QBoxLayout, \
    QListWidget, QListWidgetItem, QFrame, QLineEdit, QDialogButtonBox

class settingsDlg(QDialog):

    def __init__(self, settings, parent=None):
        super(settingsDlg, self).__init__(parent)
        self.setAttribute(Qt.WA_DeleteOnClose) #dialog will be deleted rather than hidden
        self.settingsDialog = self
        self.settings = settings
        self.create_widgets()
        self.layout_widgets()
        self.dump_dirSettingFrame.hide()
        self.barSettingFrame.hide()

        self.create_connections()
        self.readSettingsData()
        self.setWindowTitle("yavol settings")



    def create_widgets(self):

        self.TableLabel1 = QLabel("Settings")
        self.ListOfSettings = QListWidget()
        self.buttonBox = QDialogButtonBox(QDialogButtonBox.Apply |
                                          QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
        self.buttonBox.layout().setDirection(QBoxLayout.RightToLeft)
        #yara scan settings frame
        self.yaraSettingFrame = QFrame()
        self.dump_dirSettingFrame = QFrame()
        self.barSettingFrame = QFrame()

        self.labelRulesPath = QLabel('Path to YARA rules:')
        self.inputRulesPath = QLineEdit()

        self.labelFoo = QLabel('Path to dumps:')
        self.inputDumpDirPath = QLineEdit()
        self.labelBar = QLabel('Just BAR as usual')



    def layout_widgets(self):
        hLayoutButton = QHBoxLayout()
        hLayoutButton.addWidget(self.buttonBox)
        hLayoutButton.addStretch()

        vLayoutSettingsLeft = QVBoxLayout()
        vLayoutSettingsLeft.addWidget(self.TableLabel1)
        vLayoutSettingsLeft.addWidget(self.ListOfSettings)

        #yara setting frame layout
        frameLayout = QGridLayout()
        frameLayout.addWidget(self.labelRulesPath, 0, 0)
        frameLayout.addWidget(self.inputRulesPath, 0, 1)
        self.yaraSettingFrame.setLayout(frameLayout)

        #foo settings frame
        frameLayoutFoo = QGridLayout()
        frameLayoutFoo.addWidget(self.labelFoo, 0, 0)
        frameLayoutFoo.addWidget(self.inputDumpDirPath, 0, 1)
        self.dump_dirSettingFrame.setLayout(frameLayoutFoo)

        #bar settings frame
        frameLayoutBar = QVBoxLayout()
        frameLayoutBar.addWidget(self.labelBar)
        self.barSettingFrame.setLayout(frameLayoutBar)


        settingWindowsLayout = QGridLayout()

        settingWindowsLayout.addLayout(vLayoutSettingsLeft, 0, 0)
        settingWindowsLayout.addWidget(self.yaraSettingFrame, 0, 1)
        settingWindowsLayout.addWidget(self.dump_dirSettingFrame, 0, 1)
        settingWindowsLayout.addWidget(self.barSettingFrame, 0, 1)
        settingWindowsLayout.addLayout(hLayoutButton, 1, 0)

        '''
        ################################################# <-|
        #   vbox    #    vbox                           #   |
        # listOption# yaraframe                         #   | grid
        #           #                                   #   |
        #           #                                   #   |
        #################################################   |
        #            vbox     button                    #   |
        ################################################# <-|

        '''

        self.setLayout(settingWindowsLayout)

    def create_connections(self):
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)
        self.buttonBox.button(QDialogButtonBox.Apply).clicked.connect(self.apply)
        self.ListOfSettings.selectionModel().currentChanged.connect(self.setFrameVisibility)

    def accept(self):
        self.saveSettingsData()
        QDialog.accept(self)

    def apply(self):
        self.saveSettingsData()

    def setFrameVisibility(self, current, previous):

        if not previous.row() == -1:
            #hide previous frame and set current visible
            previous = str(self.ListOfSettings.item(previous.row()).text()) + "SettingFrame"
            previous = getattr(self, previous)
            previous.hide()

            #set the current visible
            current = str(self.ListOfSettings.item(current.row()).text()) + "SettingFrame"
            current = getattr(self, current)
            current.show()
            #print "Current: ", str(current.row()), self.ListOfSettings.item(current.row()).text()
            #print "Previous: ", str(previous.row()), self.ListOfSettings.item(previous.row()).text()
            #self.yaraSettingFrame.setVisible(False)

    def readSettingsData(self):
        settings = QSettings()
        settings_dict = settings.value('dictionary').toPyObject()
        # DEBUG
        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(settings_dict)

        for key in settings_dict:

            item = QListWidgetItem(
                    (QString("%1")
                     .arg(key)))
            self.ListOfSettings.addItem(item)
            if key == "yara":
                #set yara option to be 'pre-selected'
                self.ListOfSettings.setItemSelected(item, True)
                path_to_rules = settings_dict[QString('yara')][QString('rules_dir')][QString('path')]
                self.inputRulesPath.setText(path_to_rules)

            if key == "dump_dir":
                path_to_dump = settings_dict[QString('dump_dir')]
                self.inputDumpDirPath.setText(path_to_dump)

    def saveSettingsData(self):
        settings = QSettings()
        #get values of yara setting
        path_to_rules = self.inputRulesPath.text()

        #get value of the dump_dir input
        path_to_dump_dir = self.inputDumpDirPath.text()

        settings.setValue('dictionary', {'yara': {'rules_dir': {'path': path_to_rules}},
                                         'dump_dir': path_to_dump_dir,
                                         'bar': 2})

    #def getParticularSettingValue(self, keyword):
    #    #expects key for searching in settings dict, returns associated value
    #    settings = QSettings()
    #    settings_dict = settings.value('dictionary').toPyObject()#

    #    if keyword == 'yara_rules_dir':
    #        return settings_dict[QString('yara')][QString('rules_dir')][QString('path')]

    #    elif keyword == 'dump_dir':
    #        return settings_dict[QString('dump_dir')]
    #    else:
    #        return False