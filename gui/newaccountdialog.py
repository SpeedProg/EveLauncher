__author__ = 'SpeedProg'

from tkinter import END, Label, Entry, OptionMenu, StringVar, Tk

import gui.tksimpledialog


class AccountDialog(gui.tksimpledialog.Dialog):
    def __init__(self, parent, title="", login_name="", password="", path="", dx="dx11"):
        self.login_name = login_name
        self.password = password
        self.path = path
        self.dx = dx
        self.entry_ln = None
        self.variable = None
        self.entry_pw = None
        self.entry_path = None
        self.entry_dx = None
        super().__init__(parent, title)

    def body(self, master):
        Label(master, text="Login Name:").grid(row=0)
        Label(master, text="Password:").grid(row=1)
        Label(master, text="Eve Path:").grid(row=2)
        Label(master, text="DirectX:").grid(row=3)

        self.entry_ln = Entry(master)
        self.entry_pw = Entry(master, show="*")
        self.entry_path = Entry(master)
        self.variable = StringVar(master)
        self.variable.set(self.dx)
        self.entry_dx = OptionMenu(master, self.variable, "dx9", "dx11")

        self.entry_ln.insert(END, self.login_name)
        self.entry_pw.insert(END, self.password)
        self.entry_path.insert(END, self.path)

        # self.entry_path.bind("<FocusIn>", self.select_eve_path)

        self.entry_ln.grid(row=0, column=1)
        self.entry_pw.grid(row=1, column=1)
        self.entry_path.grid(row=2, column=1)
        self.entry_dx.grid(row=3, column=1)
        return self.entry_ln

        # def select_eve_path(self, event):

    # if event.widget == self.entry_path:
    #            self.path
    #            res = os.path.normpath(askdirectory(initialdir=self.path))
    #           self.path = res
    #            self.entry_path.insert(END, res)

    def apply(self):
        login_name = self.entry_ln.get()
        password = self.entry_pw.get()
        path = self.entry_path.get()
        dx = self.variable.get()
        self.result = [login_name, password, path, dx]


if __name__ == "__main__":
    root = Tk()
    d = AccountDialog(root)
    root.mainloop()
