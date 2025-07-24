# Developer tool for FireGuard - EXD
import os
import tkinter as tk
import ttkbootstrap as ttkb
from ttkbootstrap import ttk
import requests
from tkinter import messagebox

API_URL = os.environ.get("API_URL", "http://localhost:5000")

class EXDApp:
    def __init__(self):
        self.token = None
        self.root = ttkb.Window(title="EXD Developer Tool")
        self.create_login_ui()
        self.root.mainloop()

    def create_login_ui(self):
        self.clear_root()
        frm = ttk.Frame(self.root, padding=20)
        frm.pack(expand=True)

        ttk.Label(frm, text="Username").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar(value="admin")
        ttk.Entry(frm, textvariable=self.username_var, width=30).grid(row=0, column=1)

        ttk.Label(frm, text="Password").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar(value="admin")
        ttk.Entry(frm, textvariable=self.password_var, show="*", width=30).grid(row=1, column=1)

        ttk.Button(frm, text="Login", command=self.login).grid(row=2, column=0, columnspan=2, pady=10)

    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def login(self):
        user = self.username_var.get()
        password = self.password_var.get()
        try:
            resp = requests.post(f"{API_URL}/api/login", json={"username": user, "password": password}, timeout=5)
            if resp.status_code == 200:
                self.token = resp.json().get("token")
                self.create_main_ui()
            else:
                messagebox.showerror("Login Failed", f"Status: {resp.status_code}\n{resp.text}")
        except Exception as e:
            messagebox.showerror("Login Error", str(e))

    def create_main_ui(self):
        self.clear_root()
        self.root.geometry("600x400")
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=tk.X)

        self.hwid_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.hwid_var, width=40).pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="Fetch Logs", command=self.fetch_logs).pack(side=tk.LEFT)
        ttk.Button(top, text="Check Status", command=self.check_status).pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="Logout", command=self.create_login_ui).pack(side=tk.RIGHT)

        self.log_text = tk.Text(self.root, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.poll_logs()

    def fetch_logs(self):
        hwid = self.hwid_var.get().strip()
        if not hwid:
            messagebox.showerror("Error", "Enter HWID")
            return
        self.load_logs(hwid)

    def load_logs(self, hwid: str):
        if not self.token:
            return
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            resp = requests.get(f"{API_URL}/api/logs/{hwid}", headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                self.display_logs("\n".join(data.get("logs", [])))
            else:
                self.display_logs(f"Error {resp.status_code}: {resp.text}")
        except Exception as e:
            self.display_logs(f"Request error: {e}")

    def check_status(self):
        hwid = self.hwid_var.get().strip()
        if not hwid or not self.token:
            return
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            resp = requests.get(f"{API_URL}/api/status", params={"hwid": hwid}, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                messagebox.showinfo("Status", str(data))
            else:
                messagebox.showerror("Status", f"Error {resp.status_code}: {resp.text}")
        except Exception as e:
            messagebox.showerror("Status", str(e))

    def display_logs(self, text):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, text)
        self.log_text.configure(state=tk.DISABLED)

    def poll_logs(self):
        hwid = self.hwid_var.get().strip()
        if hwid:
            self.load_logs(hwid)
        self.root.after(5000, self.poll_logs)

if __name__ == "__main__":
    EXDApp()
