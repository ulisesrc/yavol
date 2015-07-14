from PyQt4.QtCore import QString, Qt
from PyQt4.QtGui import QTreeWidget, QTreeWidgetItem

import re

class Detection(object):

    def __init__(self, rule_name, process, pid=0, text=""):
        self.rule_name = QString(rule_name)
        self.process = QString(process)
        self.pid = pid
        self.text = QString(text)


class DetectionContainer(object):

    def __init__(self):
        self.detections = {}
        self.rule_names = set()
        self.pids = set()

    def detection(self, identity):
        return self.detections.get(identity)

    def addDetection(self, detection):
        self.detections[id(detection)] = detection
        self.rule_names.add(unicode(detection.rule_name))
        self.pids.add(unicode(detection.pid))


    def __len__(self):
        return len(self.detections)


    def __iter__(self):
        for detection in self.detections.values():
            yield detection


class yarascanTreeView():

    def __init__(self, data):
        self.treeWidget = QTreeWidget()
        self.data = data
        self.detections = DetectionContainer()
        self.initialLoad()


    def initialLoad(self):
        for detection in self.generateDetections():
            self.detections.addDetection(detection)
        self.populateTree()


    def populateTree(self, selectedDetection=None):
        selected = None
        self.treeWidget.clear()
        self.treeWidget.setColumnCount(3)
        self.treeWidget.setHeaderLabels(["Rule/Process", "Pid", "Text"])
        self.treeWidget.setItemsExpandable(True)
        parentRule = {}
        parentRuleProcess = {}
        for detection in self.detections:
            ancestor = parentRule.get(detection.rule_name)
            if ancestor is None:
                ancestor = QTreeWidgetItem(self.treeWidget, [detection.rule_name])
                parentRule[detection.rule_name] = ancestor
            process = detection.process
            parent = parentRuleProcess.get(process)
            if parent is None:
                parent = QTreeWidgetItem(ancestor, [process, QString("%L1").arg(detection.pid)])
                parentRuleProcess[process] = parent
                item = QTreeWidgetItem(parent, ['','', detection.text])
                item.setTextAlignment(3, Qt.AlignRight|Qt.AlignVCenter)
            if selectedDetection is not None and selectedDetection == id(detection):
                selected = item
            #self.treeWidget.expandItem(parent)
            self.treeWidget.expandItem(ancestor)
        self.treeWidget.resizeColumnToContents(0)
        self.treeWidget.resizeColumnToContents(1)
        if selected is not None:
            selected.setSelected(True)
            self.treeWidget.setCurrentItem(selected)


    def generateDetections(self):

        for x in range(len(self.data)):
            line = self.data["Owner"][x]
            matchObj = re.match(r'(.*):\s{1,}\(pid\s(\d{1,})', line, re.I)
            #if matchObj:
            #    print "matchObj.group() :", matchObj.group()
            process = matchObj.group(1)
            pid = matchObj.group(2)

            bindata = self.data["Data"][x]
            textB = ''
            for i in range(0, len(bindata), 2):
                if not i%32:
                    textB+="\n"
                else:
                    textB+=chr(int(bindata[i:i+2], 16))

            yield Detection(self.data["Rule"][x], process, pid, textB)