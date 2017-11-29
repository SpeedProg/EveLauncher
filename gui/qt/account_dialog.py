from PySide2.QtWidgets import QDialog, QApplication

__author__ = 'SpeedProg'

import os
import sys

from gui.qt.generated import account_dialog


class AccountDialog(QDialog):

    def __init__(self, title="Account", name="", pw="", dx="dx11", profile="default"):
        super().__init__()
        self.setWindowTitle(title)
        self.ui = account_dialog.Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.inp_login_name.setText(name)
        self.ui.inp_password.setText(pw)
        self.ui.inp_profile_name.setText(profile)
        self.ui.cbox_direct_x.insertItems(0, ["dx11", "dx9"])
        index = self.ui.cbox_direct_x.findText(dx)
        self.ui.cbox_direct_x.setCurrentIndex(index)
        self.result = None

    def accept(self, *args, **kwargs):
        name = self.ui.inp_login_name.text()
        password = self.ui.inp_password.text()
        profile_name = self.ui.inp_profile_name.text()
        dx = self.ui.cbox_direct_x.currentText()
        self.result = [name, password, profile_name, dx]
        super().accept(*args, **kwargs)

    def reject(self, *args, **kwargs):
        super().reject(*args, **kwargs)

    def show(self):
        if super().exec_() == QDialog.Accepted:
            return True

    def exec(self):
        if super().exec_() == QDialog.Accepted:
            return True


if __name__ == "__main__":
    app = QApplication(sys.argv)
    dia = AccountDialog("name", "pw", "dx11", "randompath")
    # dia.show()
    sys.exit(app.exec_())
