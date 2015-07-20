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

from PyQt4.QtCore import Qt
from PyQt4.QtGui import QDialog, QLabel, QVBoxLayout, QHBoxLayout, QGridLayout, QBoxLayout, \
    QListWidget, QListWidgetItem, QAbstractItemView, QPushButton, QDialogButtonBox, QSpacerItem, QSizePolicy

import os
from functools import partial

class CustListWidget(QListWidget):
    def __init__(self, parent=None):
        super(CustListWidget, self).__init__(parent)

        self.setDragDropMode(QAbstractItemView.DragDrop)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setAcceptDrops(True)

    def dropEvent(self, event):
        event.setDropAction(Qt.MoveAction)
        super(CustListWidget, self).dropEvent(event) #search for explanation


class yarascanDlg(QDialog):


    def __init__(self, path_to_rules_dir, parent=None):
        super(yarascanDlg, self).__init__(parent)
        self.setAttribute(Qt.WA_DeleteOnClose) #dialog will be deleted rather than hidden
        self.rules_dir = path_to_rules_dir
        self.create_widgets()
        self.layout_widgets()
        self.create_connections()
        self.setWindowTitle("Select rules for scan")
        self.setFixedSize(800, 600)
        self.selected_rules = [] #empty set for rule's names


    def create_widgets(self):

        self.label1 = QLabel('Available rules')
        self.label2 = QLabel('Scan with')

        self.listWidget1 = CustListWidget(self)
        self.listWidget1.setAcceptDrops(True)
        self.listWidget1.setDragEnabled(True)
        self.listWidget1.setSelectionMode(QAbstractItemView.ExtendedSelection)

        for rule in sorted(os.listdir(self.rules_dir)):
            if rule.endswith(".yar"):
                item = QListWidgetItem(rule.split(".")[0])
                self.listWidget1.addItem(item)

        self.listWidget2 = CustListWidget(self)
        self.listWidget2.setAcceptDrops(True)
        self.listWidget2.setDragEnabled(True)

        self.button1 = QPushButton(">")
        self.button1.setFixedWidth(40)

        self.button2 = QPushButton("<")
        self.button2.setFixedWidth(40)

        self.buttonBox = QDialogButtonBox(QDialogButtonBox.Ok |
                                          QDialogButtonBox.Cancel)
        self.buttonBox.layout().setDirection(QBoxLayout.RightToLeft)
        self.spacer = QSpacerItem(600, 0, QSizePolicy.Expanding, QSizePolicy.Minimum)


    def create_connections(self):
        self.button1.clicked.connect(partial(self.moveCurrentItems, 'button1'))
        self.button2.clicked.connect(partial(self.moveCurrentItems, 'button2'))
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)

    def layout_widgets(self):

        vLayout1 = QVBoxLayout()
        vLayout1.addWidget(self.label1)
        vLayout1.addWidget(self.listWidget1)

        vLayout2 = QVBoxLayout()
        vLayout2.addWidget(self.button1)
        vLayout2.addWidget(self.button2)

        vLayout3 = QVBoxLayout()
        vLayout3.addWidget(self.label2)
        vLayout3.addWidget(self.listWidget2)

        hLayout1 = QHBoxLayout()
        hLayout1.addLayout(vLayout1)
        hLayout1.addLayout(vLayout2)
        hLayout1.addLayout(vLayout3)

        hButtonLayout = QHBoxLayout()
        hButtonLayout.addItem(self.spacer)
        hButtonLayout.addWidget(self.buttonBox)

        hFinalLayout = QGridLayout()
        hFinalLayout.addLayout(hLayout1,0,0)
        hFinalLayout.addLayout(hButtonLayout,1,0)

        self.setLayout(hFinalLayout)

    def moveCurrentItems(self, source):
        if source == 'button1':
            selected_all = self.listWidget1.selectedItems()
        else:
            selected_all = self.listWidget2.selectedItems()

        for selected_item in selected_all:

            if source == 'button1':
                self.listWidget1.takeItem(self.listWidget1.row(selected_item))
                self.listWidget2.addItem(selected_item)
            else:
                self.listWidget2.takeItem(self.listWidget2.row(selected_item))
                self.listWidget1.addItem(selected_item)

    def accept(self):
        #get the list of items in listWidget2
        self.listWidget2.count()
        for i in range(self.listWidget2.count()):
            self.selected_rules.append(str(self.listWidget2.item(i).text()))
        QDialog.accept(self)