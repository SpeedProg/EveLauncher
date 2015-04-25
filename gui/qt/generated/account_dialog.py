# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'F:\source\git\PveLauncher\gui\qt\generated\account_dialog.ui'
#
# Created: Fri Apr 24 14:27:16 2015
# by: pyside-uic 0.2.15 running on PySide 1.2.2
#
# WARNING! All changes made in this file will be lost!

import sys

from PySide import QtCore, QtGui


class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(215, 181)
        self.verticalLayout = QtGui.QVBoxLayout(Dialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.formLayout = QtGui.QFormLayout()
        self.formLayout.setFieldGrowthPolicy(QtGui.QFormLayout.AllNonFixedFieldsGrow)
        self.formLayout.setLabelAlignment(QtCore.Qt.AlignLeading | QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        self.formLayout.setObjectName("formLayout")
        self.lbl_login_name = QtGui.QLabel(Dialog)
        self.lbl_login_name.setObjectName("lbl_login_name")
        self.formLayout.setWidget(0, QtGui.QFormLayout.LabelRole, self.lbl_login_name)
        self.inp_login_name = QtGui.QLineEdit(Dialog)
        self.inp_login_name.setObjectName("inp_login_name")
        self.formLayout.setWidget(0, QtGui.QFormLayout.FieldRole, self.inp_login_name)
        self.lbl_password = QtGui.QLabel(Dialog)
        self.lbl_password.setObjectName("lbl_password")
        self.formLayout.setWidget(1, QtGui.QFormLayout.LabelRole, self.lbl_password)
        self.inp_password = QtGui.QLineEdit(Dialog)
        self.inp_password.setInputMethodHints(
            QtCore.Qt.ImhHiddenText | QtCore.Qt.ImhNoAutoUppercase | QtCore.Qt.ImhNoPredictiveText)
        self.inp_password.setEchoMode(QtGui.QLineEdit.Password)
        self.inp_password.setObjectName("inp_password")
        self.formLayout.setWidget(1, QtGui.QFormLayout.FieldRole, self.inp_password)
        self.lbl_direct_x = QtGui.QLabel(Dialog)
        self.lbl_direct_x.setObjectName("lbl_direct_x")
        self.formLayout.setWidget(2, QtGui.QFormLayout.LabelRole, self.lbl_direct_x)
        self.cbox_direct_x = QtGui.QComboBox(Dialog)
        self.cbox_direct_x.setObjectName("cbox_direct_x")
        self.formLayout.setWidget(2, QtGui.QFormLayout.FieldRole, self.cbox_direct_x)
        self.lbl_eve_path = QtGui.QLabel(Dialog)
        self.lbl_eve_path.setObjectName("lbl_eve_path")
        self.formLayout.setWidget(3, QtGui.QFormLayout.LabelRole, self.lbl_eve_path)
        self.lineEdit = QtGui.QLineEdit(Dialog)
        self.lineEdit.setObjectName("lineEdit")
        self.formLayout.setWidget(3, QtGui.QFormLayout.FieldRole, self.lineEdit)
        self.verticalLayout.addLayout(self.formLayout)
        self.btn_browse = QtGui.QPushButton(Dialog)
        self.btn_browse.setObjectName("btn_browse")
        self.verticalLayout.addWidget(self.btn_browse)
        self.buttonBox = QtGui.QDialogButtonBox(Dialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel | QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout.addWidget(self.buttonBox)

        self.retranslateUi(Dialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("accepted()"), Dialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("rejected()"), Dialog.reject)
        QtCore.QObject.connect(self.btn_browse, QtCore.SIGNAL("clicked()"), Dialog.browse_eve)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "Dialog", None, QtGui.QApplication.UnicodeUTF8))
        self.lbl_login_name.setText(
            QtGui.QApplication.translate("Dialog", "Login Name:", None, QtGui.QApplication.UnicodeUTF8))
        self.lbl_password.setText(
            QtGui.QApplication.translate("Dialog", "Password:", None, QtGui.QApplication.UnicodeUTF8))
        self.lbl_direct_x.setText(
            QtGui.QApplication.translate("Dialog", "DirectX:", None, QtGui.QApplication.UnicodeUTF8))
        self.lbl_eve_path.setText(
            QtGui.QApplication.translate("Dialog", "Eve Path:", None, QtGui.QApplication.UnicodeUTF8))
        self.btn_browse.setText(
            QtGui.QApplication.translate("Dialog", "Browse for Eve", None, QtGui.QApplication.UnicodeUTF8))


if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    dia = Ui_Dialog()
    odia = QtGui.QDialog()
    dia.setupUi(odia)
    odia.show()
    sys.exit(app.exec_())