# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'F:\source\git\PveLauncher\gui\qt\generated\account_dialog.ui'
#
# Created: Wed Nov 29 17:10:24 2017
#      by: pyside2-uic  running on PySide2 2.0.0~alpha0
#
# WARNING! All changes made in this file will be lost
from PySide2 import QtWidgets, QtCore


class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(215, 181)
        self.verticalLayout = QtWidgets.QVBoxLayout(Dialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.formLayout = QtWidgets.QFormLayout()
        self.formLayout.setFieldGrowthPolicy(QtWidgets.QFormLayout.AllNonFixedFieldsGrow)
        self.formLayout.setLabelAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.formLayout.setObjectName("formLayout")
        self.lbl_login_name = QtWidgets.QLabel(Dialog)
        self.lbl_login_name.setObjectName("lbl_login_name")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.LabelRole, self.lbl_login_name)
        self.inp_login_name = QtWidgets.QLineEdit(Dialog)
        self.inp_login_name.setObjectName("inp_login_name")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.FieldRole, self.inp_login_name)
        self.lbl_password = QtWidgets.QLabel(Dialog)
        self.lbl_password.setObjectName("lbl_password")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.LabelRole, self.lbl_password)
        self.inp_password = QtWidgets.QLineEdit(Dialog)
        self.inp_password.setInputMethodHints(QtCore.Qt.ImhHiddenText|QtCore.Qt.ImhNoAutoUppercase|QtCore.Qt.ImhNoPredictiveText)
        self.inp_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.inp_password.setObjectName("inp_password")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.FieldRole, self.inp_password)
        self.lbl_direct_x = QtWidgets.QLabel(Dialog)
        self.lbl_direct_x.setObjectName("lbl_direct_x")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.LabelRole, self.lbl_direct_x)
        self.cbox_direct_x = QtWidgets.QComboBox(Dialog)
        self.cbox_direct_x.setObjectName("cbox_direct_x")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.FieldRole, self.cbox_direct_x)
        self.lbl_profile_name = QtWidgets.QLabel(Dialog)
        self.lbl_profile_name.setObjectName("lbl_profile_name")
        self.formLayout.setWidget(3, QtWidgets.QFormLayout.LabelRole, self.lbl_profile_name)
        self.inp_profile_name = QtWidgets.QLineEdit(Dialog)
        self.inp_profile_name.setObjectName("inp_profile_name")
        self.formLayout.setWidget(3, QtWidgets.QFormLayout.FieldRole, self.inp_profile_name)
        self.verticalLayout.addLayout(self.formLayout)
        self.buttonBox = QtWidgets.QDialogButtonBox(Dialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout.addWidget(self.buttonBox)

        self.retranslateUi(Dialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("accepted()"), Dialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("rejected()"), Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtWidgets.QApplication.translate("Dialog", "Dialog", None, -1))
        self.lbl_login_name.setText(QtWidgets.QApplication.translate("Dialog", "Login Name:", None, -1))
        self.lbl_password.setText(QtWidgets.QApplication.translate("Dialog", "Password:", None, -1))
        self.lbl_direct_x.setText(QtWidgets.QApplication.translate("Dialog", "DirectX:", None, -1))
        self.lbl_profile_name.setText(QtWidgets.QApplication.translate("Dialog", "Profile", None, -1))

