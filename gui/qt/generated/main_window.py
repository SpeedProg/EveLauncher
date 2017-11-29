# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'F:\source\git\PveLauncher\gui\qt\generated\main_window.ui'
#
# Created: Wed Nov 29 17:10:25 2017
#      by: pyside2-uic  running on PySide2 2.0.0~alpha0
#
# WARNING! All changes made in this file will be lost!

from PySide2 import QtCore, QtGui, QtWidgets

class Ui_main_window(object):
    def setupUi(self, main_window):
        main_window.setObjectName("main_window")
        main_window.resize(340, 212)
        self.centralwidget = QtWidgets.QWidget(main_window)
        self.centralwidget.setObjectName("centralwidget")
        self.listView = QtWidgets.QListView(self.centralwidget)
        self.listView.setGeometry(QtCore.QRect(0, 0, 251, 161))
        self.listView.setObjectName("listView")
        self.btn_launcher = QtWidgets.QPushButton(self.centralwidget)
        self.btn_launcher.setGeometry(QtCore.QRect(260, 20, 75, 23))
        self.btn_launcher.setObjectName("btn_launcher")
        self.label_server_status = QtWidgets.QLabel(self.centralwidget)
        self.label_server_status.setGeometry(QtCore.QRect(260, 0, 71, 16))
        self.label_server_status.setObjectName("label_server_status")
        self.btn_edit = QtWidgets.QPushButton(self.centralwidget)
        self.btn_edit.setGeometry(QtCore.QRect(260, 50, 75, 23))
        self.btn_edit.setObjectName("btn_edit")
        self.btn_add = QtWidgets.QPushButton(self.centralwidget)
        self.btn_add.setGeometry(QtCore.QRect(260, 80, 75, 23))
        self.btn_add.setObjectName("btn_add")
        self.btn_delete = QtWidgets.QPushButton(self.centralwidget)
        self.btn_delete.setGeometry(QtCore.QRect(260, 110, 75, 23))
        self.btn_delete.setObjectName("btn_delete")
        self.btn_clear_cache = QtWidgets.QPushButton(self.centralwidget)
        self.btn_clear_cache.setGeometry(QtCore.QRect(260, 140, 75, 23))
        self.btn_clear_cache.setObjectName("btn_clear_cache")
        self.label_client_path = QtWidgets.QLabel(self.centralwidget)
        self.label_client_path.setGeometry(QtCore.QRect(0, 170, 46, 21))
        self.label_client_path.setObjectName("label_client_path")
        self.txt_client_path = QtWidgets.QLineEdit(self.centralwidget)
        self.txt_client_path.setGeometry(QtCore.QRect(50, 170, 201, 20))
        self.txt_client_path.setReadOnly(True)
        self.txt_client_path.setObjectName("txt_client_path")
        self.btn_browse_eve = QtWidgets.QPushButton(self.centralwidget)
        self.btn_browse_eve.setGeometry(QtCore.QRect(260, 170, 75, 23))
        self.btn_browse_eve.setObjectName("btn_browse_eve")
        main_window.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(main_window)
        self.statusbar.setObjectName("statusbar")
        main_window.setStatusBar(self.statusbar)

        self.retranslateUi(main_window)
        QtCore.QObject.connect(self.btn_launcher, QtCore.SIGNAL("clicked()"), main_window.func_launch)
        QtCore.QObject.connect(self.btn_edit, QtCore.SIGNAL("clicked()"), main_window.func_edit)
        QtCore.QObject.connect(self.btn_add, QtCore.SIGNAL("clicked()"), main_window.func_add)
        QtCore.QObject.connect(self.btn_delete, QtCore.SIGNAL("clicked()"), main_window.func_delete)
        QtCore.QObject.connect(self.btn_clear_cache, QtCore.SIGNAL("clicked()"), main_window.func_clear_cache)
        QtCore.QObject.connect(self.btn_browse_eve, QtCore.SIGNAL("clicked()"), main_window.func_browse_eve)
        QtCore.QMetaObject.connectSlotsByName(main_window)

    def retranslateUi(self, main_window):
        main_window.setWindowTitle(QtWidgets.QApplication.translate("main_window", "PveLauncher", None, -1))
        self.btn_launcher.setText(QtWidgets.QApplication.translate("main_window", "Launch", None, -1))
        self.label_server_status.setText(QtWidgets.QApplication.translate("main_window", "Offline(0)", None, -1))
        self.btn_edit.setText(QtWidgets.QApplication.translate("main_window", "Edit", None, -1))
        self.btn_add.setText(QtWidgets.QApplication.translate("main_window", "Add", None, -1))
        self.btn_delete.setText(QtWidgets.QApplication.translate("main_window", "Delete", None, -1))
        self.btn_clear_cache.setText(QtWidgets.QApplication.translate("main_window", "Clear Cache", None, -1))
        self.label_client_path.setText(QtWidgets.QApplication.translate("main_window", "Eve Path", None, -1))
        self.btn_browse_eve.setText(QtWidgets.QApplication.translate("main_window", "Browse", None, -1))

