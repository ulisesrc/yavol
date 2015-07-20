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
        self.fooSettingFrame.hide()
        self.barSettingFrame.hide()

        self.create_connections()
        self.readSettingsData()
        self.setWindowTitle("yavol settings")



    def create_widgets(self):

        #self.OkButton = QPushButton("OK")
        #self.ApplyButton = QPushButton("Apply")
        #self.CancelButton = QPushButton("Cancel")
        self.TableLabel1 = QLabel("Settings")
        self.ListOfSettings = QListWidget()
        self.buttonBox = QDialogButtonBox(QDialogButtonBox.Apply |
                                          QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
        self.buttonBox.layout().setDirection(QBoxLayout.RightToLeft)
        #yara scan settings frame
        self.yaraSettingFrame = QFrame()
        self.fooSettingFrame = QFrame()
        self.barSettingFrame = QFrame()

        self.labelRulesPath = QLabel('Path to YARA rules:')
        self.inputRulesPath = QLineEdit()

        self.labelFoo = QLabel('Just FOO as usual')
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
        frameLayout.addWidget(self.labelRulesPath,0, 0)
        frameLayout.addWidget(self.inputRulesPath,0, 1)
        self.yaraSettingFrame.setLayout(frameLayout)

        #foo settings frame
        frameLayoutFoo = QVBoxLayout()
        frameLayoutFoo.addWidget(self.labelFoo)
        self.fooSettingFrame.setLayout(frameLayoutFoo)

        #bar settings frame
        frameLayoutBar = QVBoxLayout()
        frameLayoutBar.addWidget(self.labelBar)
        self.barSettingFrame.setLayout(frameLayoutBar)

        #vLayoutSettingsRight = QVBoxLayout()
        #vLayoutSettingsRight.addLayout(gLayoutSettingsRight)




        settingWindowsLayout = QGridLayout()

        settingWindowsLayout.addLayout(vLayoutSettingsLeft, 0, 0)
        settingWindowsLayout.addWidget(self.yaraSettingFrame, 0, 1)
        settingWindowsLayout.addWidget(self.fooSettingFrame, 0, 1)
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



        #layout = QVBoxLayout()
        #layout.addWidget(self.TableLabel1)
        #layout.addWidget(self.ListOfSettings)
        #layout.addLayout(buttonLayout)
        self.setLayout(settingWindowsLayout)

    def create_connections(self):
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)
        self.buttonBox.button(QDialogButtonBox.Apply).clicked.connect(self.apply)
        #self.ListOfSettings.connect(self.ListOfSettings, SIGNAL("item_clicked"), self.doNothing)
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
        #see book page 285 how to show/hide frames
        settings = QSettings()
        settings_dict = settings.value('dictionary').toPyObject()
        # DEBUG
        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(settings_dict)

        #if (dict.get('one') == 1):
        #    print "mozole mozgu, medituj!"

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

    def saveSettingsData(self):
        settings = QSettings()
        #get values of yara setting
        path_to_rules = self.inputRulesPath.text()

        settings.setValue('dictionary', {'yara': {'rules_dir': {'path': path_to_rules}},
                                         'foo': 'xxx',
                                         'bar': 2})

    def getParticularSettingValue(self, keyword):
        #expects key for searching in settings dict, returns associated value
        settings = QSettings()
        settings_dict = settings.value('dictionary').toPyObject()

        if keyword == 'yara_rules_dir':
            return settings_dict[QString('yara')][QString('rules_dir')][QString('path')]
        else:
            return False