__author__ = "Jaroslav Brtan"
__version__ = "1.0.0"

from PyQt4.QtCore import (PYQT_VERSION_STR, QFile, QFileInfo, QSettings,
                          QString, QT_VERSION_STR, QTimer, QVariant, Qt)
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from os import remove

from functools import partial

import re

import Queue as queue

import volmodule

import pprint

import settingsDlg
import yarascanDlg
import dbmodule
import yarascanTreeView

from shutil import copyfile


# TODO: add scanDlg class that will provide user with option which sigs use for scanning




def logger(func):
    def forward(*args, **kwargs):
        print "Arguments were: %s, %s" % (args, kwargs)
        return func(*args, **kwargs)

    return forward


class ResultObj(QObject):
    def __init__(self, moduleName, retValObj, volInstance):
        self.moduleName = moduleName
        self.retValObj = retValObj
        self.volInstance = volInstance


class QueueObj(QObject):
    def __init__(self, volinstance, module, filename, profile, yara_rule_name, output_path):
        self.module = module
        self.filename = filename
        self.profile = profile
        self.volinst = volinstance
        self.yara_rule = yara_rule_name
        self.output_path = output_path


class Worker(QThread):
    finished = pyqtSignal(object)

    def __init__(self, queue, callback, parent=None):
        QThread.__init__(self, parent)
        self.queue = queue
        self.finished.connect(callback)

    def __del__(self):
        self.exiting = True
        self.wait()

    def run(self):

        while True:
            query = self.queue.get()
            if query is None:  # None means exit
                print("Shutting down thread")
                return
            self.nigga(query)

    def nigga(self, query):

        result = None

        volatilityInstance = query.volinst
        moduleName = query.module
        filename = query.filename
        profile = query.profile
        yara_rule = query.yara_rule
        output_path = query.output_path
        #yara_rules_path = settingsDlg.getParticularSettingValue('yara_rules_dir')

        if volatilityInstance == None:
            volatilityInstance = volmodule.VolatilityFunctions(filename, profile, yara_rule, output_path)
        # TODO: check if db already contains volmodule output before running the module
        retObj = volatilityInstance.runModule(moduleName)

        self.finished.emit(ResultObj(moduleName, retObj, volatilityInstance))


class Window(QMainWindow):
    def __init__(self, parent=None):
        super(Window, self).__init__(parent)
        # self.thread = Worker()
        self.tabWidget = QTabWidget()
        self.tabWidget.setTabsClosable(True)
        self.tabWidget.tabCloseRequested.connect(self.closeTab)
        self.setCentralWidget(self.tabWidget)
        self.dirty = False
        self.filename = None
        self.dir = None
        self.output_path = "tmp/output.sqlite"
        self.volatilityInstance = None
        self.profile = "imageinfo"
        self.create_widgets()
        self.create_actions()
        self.settings = self.loadAppSettings()
        self.setWindowTitle("YaVol")
        # self.updateFileMenu()
        self.imageinfoShown = False
        # self.connect(self.thread, SIGNAL("output()"), self.threadDone)
        self.path_to_yara_rule = None
        self.yarascan_queue_size = 0  #used to determine when we finished scanning

    def create_widgets(self):

        logDockWidget = QDockWidget("Log", self)
        logDockWidget.setObjectName("LogDockWidget")
        logDockWidget.setAllowedAreas(Qt.LeftDockWidgetArea |
                                      Qt.RightDockWidgetArea)
        self.listWidget = QListWidget()
        logDockWidget.setWidget(self.listWidget)
        self.addDockWidget(Qt.RightDockWidgetArea, logDockWidget)

        self.sizeLabel = QLabel()
        self.sizeLabel.setFrameStyle(QFrame.StyledPanel | QFrame.Sunken)
        self.status = self.statusBar()
        self.status.setSizeGripEnabled(False)
        self.status.addPermanentWidget(self.sizeLabel)
        self.status.showMessage("Ready", 5000)

    def create_actions(self):

        fileNewAction = self.createAction("&New Analysis", self.fileOpen,
                                          QKeySequence.New, "filenew", "Analyse an image file")

        fileOpenAction = self.createAction("&Open Analysis", self.doNothing,
                                           QKeySequence.Open, "fileopen", "Restore previous analysis")

        fileSaveAction = self.createAction("&Save Analysis", self.fileSave,
                                           QKeySequence.Save, "filesave", "Restore previous analysis")

        fileExitAction = self.createAction("&Exit", self.appExit,
                                           QKeySequence.Close, None, "Exit YaVol")

        editSettingsAction = self.createAction("&Settings", self.showSettingsDialog,
                                               QKeySequence.Preferences, "settings", "YaVol Settings")

        volPslistAction = self.createAction("pslist", partial(self.actionModule, 'pslist'),
                                            None, "pslist", "List of running processes")

        volPsscanAction = self.createAction("psscan", partial(self.actionModule, 'psscan'),
                                            None, "psscan", "List of running processes")

        volDlllistAction = self.createAction("dlllist", partial(self.actionModule, 'dlllist'),
                                             None, "dlllist", "List of loaded DLLs")

        volHandlesAction = self.createAction("handles", partial(self.actionModule, 'handles'),
                                             None, "handles", "List of open handles")

        volGetsidsAction = self.createAction("getsids", partial(self.actionModule, 'getsids'),
                                             None, "getsids", "View SIDs associated with a process")

        volPrivsAction = self.createAction("privs", partial(self.actionModule, 'privs'),
                                           None, "privs", "Shows which process privileges are present")

        volVerinfoAction = self.createAction("verinfo", partial(self.actionModule, 'verinfo'),
                                             None, "verinfo", "Display the version information embedded in PE files")

        volEnumfuncAction = self.createAction("enumfunc", partial(self.actionModule, 'enumfunc'),
                                              None, "enumfunc", "Enumerates imported&exported functions from processes")

        volConnectionsAction = self.createAction("connections", partial(self.actionModule, 'connections'),
                                                 None, "connections", "List of network connections")

        volConnscanAction = self.createAction("connscan", partial(self.actionModule, 'connscan'),
                                              None, "connscan", "List of network connections")

        volSocketsAction = self.createAction("sockets", partial(self.actionModule, 'sockets'),
                                             None, "sockets", "Description missing")

        volSockscanAction = self.createAction("sockscan", partial(self.actionModule, 'sockscan'),
                                              None, "sockscan", "Description missing")

        volNetscanAction = self.createAction("netscan", partial(self.actionModule, 'netscan'),
                                             None, "netscan", "Description missing")

        volMalfindAction = self.createAction("malfind", partial(self.actionModule, 'malfind'),
                                             None, "malfind", "Description missing")

        volSvcscanAction = self.createAction("svcscan", partial(self.actionModule, 'svcscan'),
                                             None, "svcscan", "Description missing")

        volPsxviewAction = self.createAction("psxview", partial(self.actionModule, 'psxview'),
                                             None, "psxview", "Description missing")

        #yaScanallAction = self.createAction("scan image", partial(self.actionModule, 'yarascan'),
        #                                    None, None, "Scan whole image with yara")
        yaScanallAction = self.createAction("scan image", self.showYaraScanDialog,
                                            None, None, "Scan whole image with yara")

        helpAboutAction = self.createAction("about", self.showAboutInfo,
                                            None, None, "Who the hell created this crap?")

        fileMenu = self.menuBar().addMenu("&File")
        self.addActions(fileMenu, (fileNewAction, fileOpenAction, fileSaveAction, fileExitAction))

        editMenu = self.menuBar().addMenu("&Edit")
        self.addActions(editMenu, (editSettingsAction,))

        volMenu = self.menuBar().addMenu("&Volatility")
        volMenuProcesses = volMenu.addMenu("Proc&DLLs")
        self.addActions(volMenuProcesses, (volPslistAction, volPsscanAction, volDlllistAction, volHandlesAction,
                                           volGetsidsAction, volPrivsAction, volVerinfoAction, volEnumfuncAction))

        volMenuNetwork = volMenu.addMenu("Network")
        self.addActions(volMenuNetwork, (volConnectionsAction, volConnscanAction, volSocketsAction, volSockscanAction,
                                         volNetscanAction))

        volMenuMalware = volMenu.addMenu("Malware")
        self.addActions(volMenuMalware, (volMalfindAction, volSvcscanAction, volPsxviewAction))

        yaraMenu = self.menuBar().addMenu("&Yara")
        self.addActions(yaraMenu, (yaScanallAction,))

        helpMenu = self.menuBar().addMenu("&Help")
        self.addActions(helpMenu, (helpAboutAction,))

        # toolbar
        fileToolbar = self.addToolBar("File")
        fileToolbar.setObjectName("FileToolBar")
        self.addActions(fileToolbar, (fileNewAction,))

    def createAction(self, text, slot=None, shortcut=None, icon=None,
                     tip=None, checkable=False, signal="triggered()"):
        '''
        helper method for setting up actions
        '''
        action = QAction(text, self)
        if icon is not None:
            action.setIcon(QIcon(":/%s.png" % icon))
        if shortcut is not None:
            action.setShortcut(shortcut)
        if tip is not None:
            action.setToolTip(tip)
            action.setStatusTip(tip)
        if slot is not None:
            self.connect(action, SIGNAL(signal), slot)
        if checkable:
            action.setCheckable(True)
        return action

    def addActions(self, target, actions):
        for action in actions:
            if action is None:
                target.addSeparator()
            else:
                target.addAction(action)

    def loadAppSettings(self):
        settings = QSettings()
        ''' Since we passed no arguments, the names held by the application object
        are used to locate the settings information
        '''
        self.recentFiles = settings.value("RecentFiles").toStringList()
        '''method always returns a QVariant, so we must convert it to the data type we are expecting.'''
        self.restoreGeometry(
            settings.value("MainWindow/Geometry").toByteArray())
        self.restoreState(settings.value("MainWindow/State").toByteArray())

        # First app start only, set the defaults
        if settings.value('dictionary') == None:
            settings.setValue('dictionary', {'yara': {'rules_dir': {'path': '~/git/yavol_gt/yara'}},
                                             'foo': 'xxx',
                                             'bar': 2})

        return settings

    def showSettingsDialog(self):
        dialog = settingsDlg.settingsDlg(self.settings, self)
        if dialog.exec_():
            pass

    def showYaraScanDialog(self):
        #TODO: create a method that will return particular values from the QSettings object
        settings = QSettings()
        settings_dict = settings.value('dictionary').toPyObject()

        path_to_rules = settings_dict[QString('yara')][QString('rules_dir')][QString('path')]
        dialog = yarascanDlg.yarascanDlg(path_to_rules)
        if dialog.exec_():
            #check if the returned array of signatures is empty
            #and run the scan
            #DEBUG
            pprint.pprint(dialog.selected_rules)

            if len(dialog.selected_rules) > 0:
                self.yarascan_queue_size = len(dialog.selected_rules)
                for rule in dialog.selected_rules:
                    self.path_to_yara_rule = str(path_to_rules + '/' + rule + '.yar')
                    pprint.pprint(self.path_to_yara_rule)
                    self.actionModule('yarascan')

    def closeEvent(self, event):
        if self.okToContinue():
            # self.settings = QSettings()
            filename = (QVariant(QString(self.filename))
                        if self.filename is not None else QVariant())
            self.settings.setValue("LastFile", filename)
            recentFiles = (QVariant(self.recentFiles)
                           if self.recentFiles else QVariant())
            self.settings.setValue("RecentFiles", recentFiles)
            self.settings.setValue("MainWindow/Geometry", QVariant(
                self.saveGeometry()))
            self.settings.setValue("MainWindow/State", QVariant(
                self.saveState()))
            del self.settings
        else:
            event.ignore()

    def okToContinue(self):
        if self.dirty:
            reply = QMessageBox.question(self,
                                         "yavol - Unsaved Changes",
                                         "Save unsaved changes?",
                                         QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
            if reply == QMessageBox.Cancel:
                return False
            elif reply == QMessageBox.Yes:
                return self.fileSave()
        return True

    def fileOpen(self):
        if not self.okToContinue():
            return
        wdir = os.path.dirname(self.filename) if self.filename is not None else "."
        formats = ["*.img", "*.dmp"]
        fname = unicode(QFileDialog.getOpenFileName(self, "YaVol - Choose Image", wdir,
                                                    "Memory files (%s)" % " ".join(formats)))
        if fname:
            # self.loadFile(fname)
            self.filename = fname
            self.dir = wdir

            fileNameLabel = QLabel("Image: ")
            profileLabel = QLabel("Profile: ")
            fileName = QLabel(self.filename)
            self.profileSelector = QComboBox()
            self.profileSelector.addItems(['Use Imageinfo', 'VistaSP0x64', 'VistaSP0x86',
                                           'VistaSP1x64', 'VistaSP2x64', 'VistaSP2x86', 'Win2003SP0x86',
                                           'Win2003SP1x64', 'Win2003SP1x86', 'Win2003SP2x64', 'Win2003SP2x86',
                                           'Win2008R2SP0x64', 'Win2008R2SP1x64', 'Win2008SP1x64', 'Win2008SP1x86',
                                           'Win2008SP2x64', 'Win7SP0x64', 'Win7SP0x86', 'Win7SP1x64', 'Win7SP1x86',
                                           'WinXPSP1x64', 'WinXPSP2x64', 'WinXPSP2x86', 'WinXPSP3x86'])

            horizontalLayout = QHBoxLayout()
            grid = QGridLayout()
            grid.addWidget(fileNameLabel, 1, 0)
            grid.addWidget(fileName, 1, 1)
            grid.addWidget(profileLabel, 2, 0)
            grid.addWidget(self.profileSelector, 2, 1)
            spacerItem = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
            grid.addItem(spacerItem)
            horizontalLayout.addItem(grid)
            horizontalLayout.addStretch()
            # s.connect(w, SIGNAL("signalSignature"), functionName)
            #                            SIGNAL("currentIndexChanged(const QString & text)", self.addContentToWidget(self.listWidget, "profile change")
            # TODO: pridat akciu na zmenu v comboboxe ktora zapise do self.profile
            self.connect(self.profileSelector, SIGNAL("currentIndexChanged(QString)"), self.storeProfile)

            self.addTabFnc("Image", horizontalLayout)
            self.dirty = True

    def fileSave(self):

        #check the dirty flag
        if self.dirty == False:
            #show dialog that there is nothing to be saved
            #QMessageBox.warning(self, "Save analysis", "There is nothing to be saved\n"
            #                                           "...", QMessageBox.Ok)
            self.showWarningInfo("Save analysis", "There is nothing to be saved")
        else:
            # show the save dialog
            #filename = QFileDialog.getSaveFileName(self, "Save analysis", "", "Database file (*.sqlite)")
            filename, filter = QFileDialog.getSaveFileNameAndFilter(self, 'Save file', '', "Database file (*.sqlite)")
            if filename !="":
                # copy the /tmp/output.sqlite to the location selected by the user
                strFileName = str(filename)
                strFilter = str(filter)
                dst = ""
                src = ""
                if strFilter.endswith('.sqlite)'):
                    src = self.output_path
                    if strFileName.endswith('.sqlite'):
                        dst = strFileName
                    else:
                        dst = strFileName + '.sqlite'

                    try:
                        print dst
                        copyfile(src, dst)
                        #changes were stored, unset the dirty flag
                        self.dirty = False

                        self.output_path = dst

                    except IOError as e:
                        #print "I/O error({0}): {1}".format(e.errno, e.strerror)
                        self.showWarningInfo('File saving failed', e.strerror)
                    except ValueError:
                        print "Could not convert data to an integer."
                    except:
                        print "Unexpected error:", sys.exc_info()[0]
                        raise

    def appExit(self):
        #check the status of the dirty flag
        if self.dirty == False:

            #clean the temp folder
            remove('tmp/output.sqlite')
            #and quit
            QCoreApplication.instance().quit()
        else:
            if self.okToContinue():
                remove('tmp/output.sqlite')
                QCoreApplication.instance().quit()

    def storeProfile(self, profile):
        # If volatility class was called with a profile value
        # instance was stored in volatilityInstance. In case that user wants to use another profile,
        # previous instance must be dropped
        if self.volatilityInstance:
            self.volatilityInstance = None
        self.profile = unicode(profile)
        self.displayInLog("Profile changed: " + unicode(profile))

    def handle_result(self, result):
        # this method is a callback which should
        # process the data from the worker thread
        moduleName = result.moduleName

        # in case we have run a module for the first time
        # worker thread will return handle to the volatility instance
        # storing it we could save some time with the next run
        if not self.volatilityInstance:
            if result.volInstance:
                self.volatilityInstance = result.volInstance

        #if the result comes from yarascan,
        # 1) check if the value of the yara_scan_queue_size > 1
        # 1a) lower its size by one
        # 1aa) send the result to buffer
        # 2) if the value of yara_scan_queue_size after the substraction is eq 0
        #    send the buffer to processing
        if moduleName == 'yarascan': # yarascan module output will be taken special care
            if self.yarascan_queue_size > 1:
                self.yarascan_queue_size -= 1
            else:
                #memory image scan was finished with all selected rules
                # get the data from db and show it to user in a treeview
                self.yarascan_queue_size = 0

                db = dbmodule.sqlitequery(moduleName, self.output_path)
                data = db.getData()
                self.addToTab(moduleName, 'tree', data)

        else:   #output of the rest of the modules will be shown right away in a tab
            # textVal is used only with imageinfo module
            # (and some others that don't write to sqlite)
            # If it is defined display it in a new tab
            if result.retValObj.textVal:
                self.addToTab(moduleName, 'list', result.retValObj.textVal)
            else:
                # textVal is not defined, this means data was stored in DB
                # we need to get them
                db = dbmodule.sqlitequery(moduleName, self.output_path)
                data = db.getData()
                self.addToTab(moduleName, 'table', data)
                # pprint.pprint(data)

    def yarascanParser(self):
        print("yarascanParser called!")

    def thread_process(self, volinstance, moduleName, filename, profile, yara_rule_path, output_path):
        MAX_CORES = 2
        self.queue = queue.Queue()
        self.threads = []
        for i in range(MAX_CORES):
            thread = Worker(self.queue, self.handle_result)
            self.threads.append(thread)
            thread.start()

        query = QueueObj(volinstance, moduleName, filename, profile, yara_rule_path, output_path)

        self.queue.put(query)

        for _ in range(MAX_CORES):  # Tell the workers to shut down
            self.queue.put(None)

    def actionModule(self, moduleName):

        # check if the selected image profile supports this module
        compatibilityCheck = re.match('Vista|Win2008|Win7', self.profile, flags=0)

        if moduleName in ['connections', 'connscan', 'sockscan', 'sockets']:
            if compatibilityCheck:
                self.displayInLog("Error: This module can't be use with this profile")
                return False

        self.status.showMessage("Creating %s output" % moduleName, 5000)
        self.displayInLog("%s with a profile called!" % moduleName)

        if self.volatilityInstance != None:
            self.displayInLog("Info: Volatility instance found")
            if self.path_to_yara_rule:
                self.thread_process(self.volatilityInstance, moduleName, self.filename, self.profile,
                                    self.path_to_yara_rule, self.output_path)
            else:
                self.thread_process(self.volatilityInstance, moduleName, self.filename, self.profile,
                                    None, self.output_path)
        else:
            self.displayInLog("Info: Volatility instance missing!")
            if self.path_to_yara_rule:
                self.thread_process(None, moduleName, self.filename, self.profile, self.path_to_yara_rule, self.output_path)
            else:
                self.thread_process(None, moduleName, self.filename, self.profile, None, self.output_path)

    def addTabFnc(self, name, layout):
        self.widget = QWidget()
        self.widget.setLayout(layout)
        self.tabWidget.addTab(self.widget, name)
        self.tabWidget.setCurrentWidget(self.widget)

    def addToTab(self, tabName, type, content):
        tabLayout = QHBoxLayout()
        if type == 'list':
            #listWidget = QListWidget()
            textEditWidget = QTextEdit()
            #item = QListWidgetItem(content)
            textEditWidget.insertPlainText(content)
            #listWidget.addItem(item)
            #tabLayout.addWidget(listWidget)
            textEditWidget.setReadOnly(True)
            tabLayout.addWidget(textEditWidget)

        elif type == 'tree':
            #yarascan
            yarascanClass= yarascanTreeView.yarascanTreeView(content)
            tabLayout.addWidget(yarascanClass.treeWidget)

        elif type == 'table':
            # number of columns depends on number of keys in dict
            num_of_columns = len(content)
            num_of_rows = len(content[content.keys()[0]])
            tableWidget = QTableWidget(num_of_rows, num_of_columns)

            horHeaders = []
            for n, key in enumerate(content.keys()):
                horHeaders.append(key)
                for m, item in enumerate(content[key]):
                    newitem = QTableWidgetItem(item)
                    tableWidget.setItem(m, n, newitem)
            tableWidget.setHorizontalHeaderLabels(horHeaders)
            tableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers) # disable editing items in table
            tabLayout.addWidget(tableWidget)

        self.addTabFnc(tabName, tabLayout)
        # self.dirty = True

    def closeTab(self, currentIndex):
        currentQWidget = self.tabWidget.widget(currentIndex)
        currentQWidget.deleteLater()
        self.tabWidget.removeTab(currentIndex)

    def showAboutInfo(self):
        QMessageBox.about(self, "About yavol",
                          "yavol version %s\n\nCopyright(c) 2015 by %s\n" % (__version__, __author__))

    def showWarningInfo(self, warning_title, warning_text):
        QMessageBox.warning(self, warning_title, warning_text, QMessageBox.Ok)

    def displayInLog(self, content):
        self.listWidget.addItem(content)

    def doNothing(self):
        self.dirty = True
        self.displayInLog("Nothing was done, really")

