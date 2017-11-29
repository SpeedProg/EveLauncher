#! /usr/bin/env python


from tkinter import messagebox, END
import os
from urllib.error import *
import urllib.request as request
from threading import Thread
import configparser
import re
from tkinter.messagebox import showinfo

from eve.account import EveLoginManager, EveAccount
from gui.newaccountdialog import AccountDialog


def gui_edit():
    items = map(int, w.acc_list.curselection())
    for idx in items:
        account = login_manager.accounts[w.acc_list.get(idx)]
        dialog = AccountDialog(root, "Edit account", account.login_name,
                               account.plain_password(login_manager.coder),
                               account.eve_path, account.direct_x)
        if dialog.result is not None:
            path = dialog.result[2]
            if not path.endswith(os.sep):
                path = path + os.sep
            account = EveAccount(dialog.result[0], dialog.result[1], login_manager.coder, path,
                                 None, None, dialog.result[3])
            login_manager.add_account(account)


def gui_login():
    items = map(int, w.acc_list.curselection())
    for idx in items:
        try:
            login_manager.login(w.acc_list.get(idx))  # TODO: write console cbs
        except URLError as e:
            messagebox.showerror("Error", e.msg)


def gui_add():
    dialog = AccountDialog(root, "New Account")
    if dialog.result is not None:
        path = dialog.result[2]
        if not path.endswith(os.sep):
            path = path + os.sep
        account = EveAccount(dialog.result[0], dialog.result[1], login_manager.coder, path,
                             None, None, dialog.result[3])
        login_manager.add_account(account)
        w.acc_list.insert(END, account.login_name)


def gui_delete():
    items = map(int, w.acc_list.curselection())
    for idx in items:
        login_manager.del_account(w.acc_list.get(idx))

    items = map(int, w.acc_list.curselection())
    for idx in items:
        w.acc_list.delete(idx)


def gui_clear_cache():
    login_manager.clear_cache()


def init(top, gui, crypter):
    global w, top_level, root, login_manager
    w = gui
    top_level = top
    root = top
    login_manager = EveLoginManager(crypter)
    login_manager.load()
    for account_name in login_manager.accounts:
        gui.acc_list.insert(END, account_name)

    version_thread = Thread(target=check_eve_version)
    version_thread.start()


def check_eve_version():
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
    for acc in login_manager.accounts:
        up_to_date = check_eve_version_for_account(version_string, login_manager.accounts[acc])
        if not up_to_date:
            out_of_date_eves.append(login_manager.accounts[acc].eve_path)

    if len(out_of_date_eves) > 0:
        info_msg = "Folloing Eve Clients are out of date:"
        for path in out_of_date_eves:
            info_msg += "\n" + path
        showinfo("Eve Clients out of date", info_msg)


def check_eve_version_for_account(current_version, account):
    config = configparser.ConfigParser()
    config.read(account.eve_path + "start.ini")
    local_version = config['main']['build']
    local_version = local_version.strip()
    print("remote build: " + current_version + " -> local: " + local_version)
    if local_version != current_version:
        return False

    return True


def close():
    login_manager.save()


def destroy_window():
    # Function which closes the window.
    global top_level
    top_level.destroy()
    top_level = None


