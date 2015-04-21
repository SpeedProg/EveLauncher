# coding=utf-8
import argparse
import os
from tkinter import *

from eve.account import *
from gui import mainwindow
from gui import mainwindow_support


__version__ = "0.0.3"


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
    print("Login with "+args.username)
    crypt = Coding(args.encryption.encode('utf-8'))
    login_manager = EveLoginManager(crypt)
    login_manager.load()
    login_manager.login(args.username)


def vp_start_gui(crypt):
    global val, w, root
    root = Tk()
    root.title('PveLauncher')
    geom = "259x185+496+300"
    root.geometry(geom)
    w = mainwindow.PveLauncher(root)
    mainwindow_support.init(root, w, crypt)
    root.mainloop()


def gui(args):
    crypt = Coding(args.encryption.encode('utf-8'))
    vp_start_gui(crypt)


def entry():
    crypt_key = u"0238jh74ngz23v84m90fcqewmn4f89"
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
    parser_add.add_argument("-dx", "--directx", choices="dx9,dx11", help="DirectX version to use, xd11(default) or dx9", nargs='?',
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