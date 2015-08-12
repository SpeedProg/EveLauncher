# coding=utf-8
import argparse
import os
#  from tkinter import *
#  from gui import mainwindow
#  from gui import mainwindow_support
#
#  from gui.systrayicon import SysTrayIcon

from PySide.QtGui import QApplication

from eve.account import *

from gui.qt.window import ControlMainWindow, QtSingleApplication
import sys

import threading
from threading import Thread
from eve.eveapi import EveApi


__version__ = "0.0.15"


def add(args):
    crypt = Coding(args.encryption.encode('utf-8'))
    login_manager = EveLoginManager(crypt)
    login_manager.load()
    if not args.path.endswith(os.sep):
        args.path += os.sep
    account = EveAccount(args.username, args.password, crypt, args.path, None, None, args.directx)
    login_manager.add_account(account)
    login_manager.save()
    print("User added")


def login(args):
    print("Login with " + args.username)
    crypt = Coding(args.encryption.encode('utf-8'))
    login_manager = EveLoginManager(crypt)
    login_manager.load()
    login_manager.login(args.username)  # TODO: write console cbs
#
#
# class GuiStarter():
#     def __init__(self, crypt):
#         self.root = Tk()
#         self.root.bind('<Unmap>', self.minimize_event)
#         self.root.title('PveLauncher')
#         geom = "259x185+496+300"
#         self.root.geometry(geom)
#         eve_api = EveApi()
#         self.pvelauncher = mainwindow.PveLauncher(self.root)
#         mainwindow_support.init(self.root, self.pvelauncher, crypt)
#         self.eve_api = eve_api
#         self.timer = None
#         t = Thread(target=GuiStarter.sysicon, args=(self,))
#         t.start()
#
#     def sysicon(self):
#         menu_options = (
#             ('Show', None, self.show_window),
#         )
#         SysTrayIcon("tray.ico", "Eve Sucks", menu_options, on_quit=self.wth, default_menu_index=1)
#         self.root.destroy()
#         self.root.quit()
#
#     def show_window(self, tray):
#         self.root.state('normal')
#         pass
#
#     def wth(self, tray):
#         pass
#
#     def minimize_event(self, event):
#         # minimize
#         if event.type == '18' and event.widget == self.root:
#             self.root.state("withdrawn")
#
#     def start_gui(self):
#         self.timer = threading.Timer(0.001, self.update_server_status,
#                                      kwargs={'window': self.pvelauncher, 'api': self.eve_api}).start()
#         self.root.mainloop()
#         if self.timer is not None:
#             self.timer.cancel()
#             mainwindow_support.close()
#         os._exit(0)
#
#     def update_server_status(self, window, api):
#         status = api.get_server_status()
#         if status.server_open:
#             status_text = "Online"
#         else:
#             status_text = "Offline"
#
#         window.set_server_status("{0}({1:d})".format(status_text, status.online_players))
#         self.timer = threading.Timer(60.0, self.update_server_status, kwargs={'window': window, 'api': api})
#         self.timer.start()


class QtStarter:
    def __init__(self, crypter):
        self.app = QtSingleApplication('17660D78-290B-4282-8741-24595B156CB1', sys.argv)
        if self.app.isRunning():
            sys.exit(0)
        self.window = ControlMainWindow(crypter)
        self.eve_api = EveApi()
        self.timer = None

    def start_gui(self):
        self.timer = threading.Timer(0.001, self.update_server_status,
                                     kwargs={'window': self.window, 'api': self.eve_api}).start()
        self.window.show()
        ret = self.app.exec_()
        if self.timer is not None:
            self.timer.cancel()
        return ret

    def update_server_status(self, window, api):
        try:
            status = api.get_server_status()
            if status.server_open:
                status_text = "Online"
            else:
                status_text = "Offline"

            window.set_server_status(status_text, status.online_players)

        except URLError:
            window.set_server_status("Failed ", 0)

        self.timer = threading.Timer(10.0, self.update_server_status, kwargs={'window': window, 'api': api})
        self.timer.start()


# def vp_start_gui(crypt):
#     gui_starter = GuiStarter(crypt)
#     gui_starter.start_gui()


def gui(args):
    crypt = Coding(args.encryption.encode('utf-8'))
    # vp_start_gui(crypt)
    starter = QtStarter(crypt)
    starter.start_gui()


def entry():
    crypt_key = u"0238jh74ngz23v84m90fcqewmn4f89"
    #  http.client.HTTPConnection.debuglevel = 1  # debug requests
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--encryption",
                        help="Key used for password encryption/decryption, if not given uses default",
                        nargs='?', default=crypt_key)
    subparsers = parser.add_subparsers()

    # parser for add
    parser_add = subparsers.add_parser('add', help='add -h for help')
    parser_add.add_argument("-p", "--path", help="Path to eve folder e.g. C:\\Program Files (x86)\\Eve\\",
                            required=True)
    parser_add.add_argument("-n", "--username", help="Eve login username", required=True)
    parser_add.add_argument("-a", "--password", help="Eve login password, use this once to store an encrypted version",
                            required=True)
    parser_add.add_argument("-dx", "--directx", choices="dx9,dx11", help="DirectX version to use, xd11(default) or dx9",
                            nargs='?',
                            default='dx11')
    parser_add.set_defaults(func=add)

    # parser for login
    parser_login = subparsers.add_parser('login', help='login -h for help')
    parser_login.add_argument("-n", "--username", help="Eve login username", required=True)
    parser_login.set_defaults(func=login)

    # parser for gui
    parser_gui = subparsers.add_parser('gui', help="start the gui,  for help 'gui -h'")
    parser_gui.set_defaults(func=gui)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        gui(args)


if __name__ == "__main__":
    entry()
