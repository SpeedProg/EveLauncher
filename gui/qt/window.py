__author__ = 'SpeedProg'

from threading import Thread
import sys
import configparser
from urllib import request
import re
import os
from queue import Queue

from PySide import QtGui
from PySide.QtGui import QApplication
from PySide.QtCore import QTimer, QEvent, SLOT, QTextStream
from PySide.QtCore import QMetaObject, Slot, Qt, QObject, Signal
from PySide.QtNetwork import *

from gui.qt.generated.main_window import Ui_MainWindow
from eve.account import EveLoginManager, EveAccount
from gui.qt.account_dialog import AccountDialog


class Invoker(QObject):
    def __init__(self):
        super(Invoker, self).__init__()
        self.queue = Queue()

    def invoke(self, func, *args):
        f = lambda: func(*args)
        self.queue.put(f)
        QMetaObject.invokeMethod(self, "handler", Qt.QueuedConnection)

    @Slot()
    def handler(self):
        f = self.queue.get()
        f()


invoker = Invoker()


def invoke_in_main_thread(func, *args):
    invoker.invoke(func, *args)


class QtSingleApplication(QApplication):
    messageReceived = Signal()

    def __init__(self, id, *argv):
        super(QtSingleApplication, self).__init__(*argv)
        self._id = id
        self._activationWindow = None
        self._activateOnMessage = False

        # Is there another instance running?
        self._outSocket = QLocalSocket()
        self._outSocket.connectToServer(self._id)
        self._isRunning = self._outSocket.waitForConnected()

        if self._isRunning:
            # Yes, there is.
            self._outStream = QTextStream(self._outSocket)
            self._outStream.setCodec('UTF-8')
        else:
            # No, there isn't.
            self._outSocket = None
            self._outStream = None
            self._inSocket = None
            self._inStream = None
            self._server = QLocalServer()
            self._server.listen(self._id)
            self._server.newConnection.connect(self._onNewConnection)

    def isRunning(self):
        return self._isRunning

    def id(self):
        return self._id

    def activationWindow(self):
        return self._activationWindow

    def setActivationWindow(self, activationWindow, activateOnMessage = True):
        self._activationWindow = activationWindow
        self._activateOnMessage = activateOnMessage

    def activateWindow(self):
        if not self._activationWindow:
            return
        self._activationWindow.setWindowState(
            self._activationWindow.windowState() & ~Qt.WindowMinimized)
        self._activationWindow.raise_()
        self._activationWindow.activateWindow()

    def sendMessage(self, msg):
        if not self._outStream:
            return False
        self._outStream << msg << '\n'
        self._outStream.flush()
        return self._outSocket.waitForBytesWritten()

    def _onNewConnection(self):
        if self._inSocket:
            self._inSocket.readyRead.disconnect(self._onReadyRead)
        self._inSocket = self._server.nextPendingConnection()
        if not self._inSocket:
            return
        self._inStream = QTextStream(self._inSocket)
        self._inStream.setCodec('UTF-8')
        self._inSocket.readyRead.connect(self._onReadyRead)
        if self._activateOnMessage:
            self.activateWindow()

    def _onReadyRead(self):
        while True:
            msg = self._inStream.readLine()
            if not msg:
                break
            self.messageReceived.emit(msg)


class ControlMainWindow(QtGui.QMainWindow):
    def __init__(self, crypter):
        super(ControlMainWindow, self).__init__(None)
        self.icon = QtGui.QSystemTrayIcon()
        self.icon.setIcon(QtGui.QIcon('./eve_tray.png'))
        self.icon.show()
        self.setWindowIcon(QtGui.QIcon('./eve_tray.png'))
        self.setWindowTitle('Pve Launcher')
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.icon.activated.connect(self.activate)
        self.account_list_model = QtGui.QStringListModel()
        self.ui.listView.setModel(self.account_list_model)

        self.login_manager = EveLoginManager(crypter)

        self.init_none_ui(crypter)

    def init_none_ui(self, crypter):

        self.login_manager.load()
        acc_list = []
        for account_name in self.login_manager.accounts:
            acc_list.append(account_name)

        self.account_list_model.setStringList(acc_list)
        version_thread = Thread(target=self.check_eve_version)
        version_thread.start()

    def closeEvent(self, event):
        self.login_manager.save()

    def changeEvent(self, event):
        if event.type() == QEvent.WindowStateChange:
            if self.windowState() & Qt.WindowMinimized:
                self.icon.show()
                QTimer.singleShot(0, self, SLOT('hide()'))
                event.ignore()

    def func_launch(self):
        indexes = self.ui.listView.selectedIndexes()
        # i get QModelIndex here
        for idx in indexes:
            try:
                self.login_manager.login(idx.data(), self.get_auth_code, self.get_charname)
            except Exception as e:
                invoke_in_main_thread(QtGui.QMessageBox.critical, self, "Launch Error",
                                      e.__str__(), QtGui.QMessageBox.Ok)

    def func_edit(self):
        indexes = self.ui.listView.selectedIndexes()
        # i get QModelIndex here
        for idx in indexes:
            account = self.login_manager.accounts[idx.data()]
            dialog = AccountDialog("Edit Account", account.login_name,
                                   account.plain_password(self.login_manager.coder), account.direct_x, account.eve_path)
            if dialog.show():
                # result = [name, password, path, dx]:
                path = dialog.result[2]
                if not path.endswith(os.sep):
                    path = path + os.sep
                account = EveAccount(dialog.result[0], dialog.result[1], self.login_manager.coder, path,
                                     None, None, dialog.result[3])
                self.login_manager.add_account(account)

    def func_add(self):
        dialog = AccountDialog("Create Account")
        if dialog.show():
            # [name, password, path, dx]
            path = dialog.result[2]
            if not path.endswith(os.sep):
                path = path + os.sep
            account = EveAccount(dialog.result[0], dialog.result[1], self.login_manager.coder, path,
                                 None, None, dialog.result[3])
            self.login_manager.add_account(account)
            acc_list = self.account_list_model.stringList()
            acc_list.append(account.login_name)
            self.account_list_model.setStringList(acc_list)

    def func_delete(self):
        indexes = self.ui.listView.selectedIndexes()
        # i get QModelIndex here
        model = self.ui.listView.model()
        for idx in indexes:
            self.login_manager.del_account(idx.data())
            model.removeRow(idx.row())

    def func_clear_cache(self):
        self.login_manager.clear_cache()

    def activate(self, reason):
        if reason == 2:
            self.showNormal()
            self.raise_()
            self.activateWindow()
            #self.setWindowState(Qt.WindowNoState)
            #self.activateWindow()

    def check_eve_version(self):
        headers = {'User-Agent': EveLoginManager.useragent}
        version_url = "http://client.eveonline.com/patches/premium_patchinfoTQ_inc.txt"
        req = request.Request(version_url, headers=headers)
        response = request.urlopen(req)
        version_data = response.read().decode('utf-8')
        match = re.match("BUILD:(\\d+)", version_data)

        if match is None:
            return None

        version_string = match.group(1)
        version_string = version_string.strip()
        out_of_date_eves = []
        for acc in self.login_manager.accounts:
            up_to_date = check_eve_version_for_account(version_string, self.login_manager.accounts[acc])
            if not up_to_date:
                out_of_date_eves.append(self.login_manager.accounts[acc].eve_path)

        if len(out_of_date_eves) > 0:
            info_msg = "Folloing Eve Clients are out of date:"
            for path in out_of_date_eves:
                info_msg += "\n" + path
            invoke_in_main_thread(QtGui.QMessageBox.information, self, "Eve Clients out of date",
                                  info_msg, QtGui.QMessageBox.Ok)

    def set_server_status(self, text, number):
        self.ui.label_server_status.setText(
            QtGui.QApplication.translate("main_window", text, None, QtGui.QApplication.UnicodeUTF8)
            + "({0:d})".format(number))

    def get_auth_code(self, opener, request):
        """
        :param mailurl: url to call for sending an authcode per mail
        :return: the authcode
        """
        inputDialog = QtGui.QInputDialog(self)
        inputDialog.setInputMode(QtGui.QInputDialog.TextInput)
        inputDialog.setCancelButtonText("Send Auth Mail")
        inputDialog.setLabelText("Please enter your Authcode")
        inputDialog.setWindowTitle("TwoFactorAuth")
        inputDialog.setModal(True)

        response = None

        if inputDialog.exec_() == QtGui.QInputDialog.Rejected:  # send mail
            response = opener.open(request)
        else:
            return response, inputDialog.textValue().strip()

        inputDialog.setCancelButtonText("Cancel")
        if inputDialog.exec_() == QtGui.QInputDialog.Rejected:
            return response, None
        return response, inputDialog.textValue().strip()

    def get_charname(self):
        """
        :param mailurl: url to call for sending an authcode per mail
        :return: the authcode
        """
        inputDialog = QtGui.QInputDialog(self)
        inputDialog.setInputMode(QtGui.QInputDialog.TextInput)
        inputDialog.setLabelText("Please enter a Charname")
        inputDialog.setWindowTitle("Charname Challange")
        inputDialog.setModal(True)

        response = None

        if inputDialog.exec_() == QtGui.QInputDialog.Rejected:
            return None

        return inputDialog.textValue().strip()

def check_eve_version_for_account(current_version, account):
    config = configparser.ConfigParser()
    config.read(account.eve_path + "start.ini")
    if 'main' in config.sections():
        local_version = config['main']['build']
        local_version = local_version.strip()
        if local_version != current_version:
            return False

    return True


if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    mySW = ControlMainWindow()
    mySW.show()
    sys.exit(app.exec_())