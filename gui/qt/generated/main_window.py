# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'F:\source\git\PveLauncher\gui\qt\main_window.ui'
#
# Created: Thu Apr 23 17:27:00 2015
# by: pyside-uic 0.2.15 running on PySide 1.2.2
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui


class Ui_MainWindow(object):
    def setupUi(self, main_window):
        main_window.setObjectName("main_window")
        main_window.resize(340, 183)
        self.centralwidget = QtGui.QWidget(main_window)
        self.centralwidget.setObjectName("centralwidget")
        self.listView = QtGui.QListView(self.centralwidget)
        self.listView.setGeometry(QtCore.QRect(0, 0, 251, 161))
        self.listView.setObjectName("listView")
        self.btn_launcher = QtGui.QPushButton(self.centralwidget)
        self.btn_launcher.setGeometry(QtCore.QRect(260, 20, 75, 23))
        self.btn_launcher.setObjectName("btn_launcher")
        self.label_server_status = QtGui.QLabel(self.centralwidget)
        self.label_server_status.setGeometry(QtCore.QRect(260, 0, 71, 16))
        self.label_server_status.setObjectName("label_server_status")
        self.btn_edit = QtGui.QPushButton(self.centralwidget)
        self.btn_edit.setGeometry(QtCore.QRect(260, 50, 75, 23))
        self.btn_edit.setObjectName("btn_edit")
        self.btn_add = QtGui.QPushButton(self.centralwidget)
        self.btn_add.setGeometry(QtCore.QRect(260, 80, 75, 23))
        self.btn_add.setObjectName("btn_add")
        self.btn_delete = QtGui.QPushButton(self.centralwidget)
        self.btn_delete.setGeometry(QtCore.QRect(260, 110, 75, 23))
        self.btn_delete.setObjectName("btn_delete")
        self.btn_clear_cache = QtGui.QPushButton(self.centralwidget)
        self.btn_clear_cache.setGeometry(QtCore.QRect(260, 140, 75, 23))
        self.btn_clear_cache.setObjectName("btn_clear_cache")
        main_window.setCentralWidget(self.centralwidget)
        self.statusbar = QtGui.QStatusBar(main_window)
        self.statusbar.setObjectName("statusbar")
        main_window.setStatusBar(self.statusbar)

        self.retranslateUi(main_window)
        QtCore.QObject.connect(self.btn_launcher, QtCore.SIGNAL("clicked()"), main_window.func_launch)
        QtCore.QObject.connect(self.btn_edit, QtCore.SIGNAL("clicked()"), main_window.func_edit)
        QtCore.QObject.connect(self.btn_add, QtCore.SIGNAL("clicked()"), main_window.func_add)
        QtCore.QObject.connect(self.btn_delete, QtCore.SIGNAL("clicked()"), main_window.func_delete)
        QtCore.QObject.connect(self.btn_clear_cache, QtCore.SIGNAL("clicked()"), main_window.func_clear_cache)
        QtCore.QMetaObject.connectSlotsByName(main_window)

    def retranslateUi(self, main_window):
        main_window.setWindowTitle(
            QtGui.QApplication.translate("main_window", "PveLauncher", None, QtGui.QApplication.UnicodeUTF8))
        self.btn_launcher.setText(
            QtGui.QApplication.translate("main_window", "Launch", None, QtGui.QApplication.UnicodeUTF8))
        self.label_server_status.setText(
            QtGui.QApplication.translate("main_window", "Offline", None, QtGui.QApplication.UnicodeUTF8))
        self.btn_edit.setText(QtGui.QApplication.translate("main_window", "Edit", None, QtGui.QApplication.UnicodeUTF8))
        self.btn_add.setText(QtGui.QApplication.translate("main_window", "Add", None, QtGui.QApplication.UnicodeUTF8))
        self.btn_delete.setText(
            QtGui.QApplication.translate("main_window", "Delete", None, QtGui.QApplication.UnicodeUTF8))
        self.btn_clear_cache.setText(
            QtGui.QApplication.translate("main_window", "Clear Cache", None, QtGui.QApplication.UnicodeUTF8))


