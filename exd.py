# Developer tool for FireGuard - EXD
import os
import tkinter as tk
import ttkbootstrap as ttkb
from ttkbootstrap import ttk
from tkinter import messagebox, simpledialog
import requests

API_URL = os.environ.get("API_URL", "https://fireguard-antivirus.onrender.com")

class EXDApp:
    def __init__(self):
        self.token = None
        self.log_job = None
        self.root = ttkb.Window(title="EXD Developer Tool")
        self.create_login_ui()
        self.root.mainloop()

    def create_login_ui(self):
        self.clear_root()
        frm = ttk.Frame(self.root, padding=20)
        frm.pack(expand=True)

        ttk.Label(frm, text="Username").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.username_var, width=30).grid(row=0, column=1)

        ttk.Label(frm, text="Password").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.password_var, show="*", width=30).grid(row=1, column=1)

        ttk.Button(frm, text="Login", command=self.login).grid(row=2, column=0, columnspan=2, pady=10)

    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        if self.log_job:
            self.root.after_cancel(self.log_job)
            self.log_job = None

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

        ttk.Button(top, text="Refresh Clients", command=self.load_clients).pack(side=tk.LEFT)
        ttk.Button(top, text="Fetch Logs", command=self.fetch_logs).pack(side=tk.LEFT)
        ttk.Button(top, text="Push Update", command=self.push_update).pack(side=tk.LEFT)
        ttk.Button(top, text="Toggle Ban", command=self.toggle_ban).pack(side=tk.LEFT)
        ttk.Button(top, text="Remove Client", command=self.remove_client).pack(side=tk.LEFT)
        ttk.Button(top, text="Check License", command=self.license_check).pack(side=tk.LEFT)
        ttk.Button(top, text="Add License", command=self.add_license).pack(side=tk.LEFT)
        ttk.Button(top, text="Remove License", command=self.remove_license).pack(side=tk.LEFT)
        ttk.Button(top, text="Ban HWID", command=self.ban_hwid).pack(side=tk.LEFT)
        ttk.Button(top, text="Logout", command=self.create_login_ui).pack(side=tk.RIGHT)

        self.clients_tree = ttk.Treeview(self.root, columns=("username", "hwid", "banned"), show="headings")
        for col in ("username", "hwid", "banned"):
            self.clients_tree.heading(col, text=col.title())
        self.clients_tree.pack(fill=tk.X, padx=10, pady=10)

        self.log_text = tk.Text(self.root, height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.log_text.bind("<Key>", lambda e: "break")

        copy_btn = ttk.Button(top, text="Copy Logs", command=self.copy_logs)
        copy_btn.pack(side=tk.RIGHT)

        self.load_clients()
        self.poll_logs()

    def fetch_logs(self):
        item = self.clients_tree.selection()
        hwid = None
        if item:
            hwid = self.clients_tree.item(item[0]).get("values", [None, None])[1]
        self.load_logs(hwid)

    def load_logs(self, hwid=None):
        if not self.token:
            return
        headers = {"Authorization": f"Bearer {self.token}"}
        params = {"hwid": hwid} if hwid else {}
        try:
            resp = requests.get(
                f"{API_URL}/api/logs", headers=headers, params=params, timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                self.display_logs("\n".join(data.get("logs", [])))
            else:
                self.display_logs(f"Error {resp.status_code}: {resp.text}")
        except Exception as e:
            self.display_logs(f"Request error: {e}")

    def display_logs(self, text):
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, text)

    def copy_logs(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.log_text.get("1.0", tk.END))
    def poll_logs(self):
        self.fetch_logs()
        self.log_job = self.root.after(5000, self.poll_logs)
    def load_clients(self):
        if not self.token:
            return
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            resp = requests.get(f"{API_URL}/api/clients", headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json().get("clients", [])
                self.clients_tree.delete(*self.clients_tree.get_children())
                for c in data:
                    self.clients_tree.insert("", tk.END, values=(c.get("username"), c.get("hwid"), c.get("banned")))
            else:
                messagebox.showerror("Error", resp.text)
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def license_check(self):
        if not self.token:
            return
        item = self.clients_tree.selection()
        if not item:
            messagebox.showwarning("License", "Select a client first")
            return
        username = self.clients_tree.item(item[0]).get("values")[0]
        key = simpledialog.askstring("License Check", "Enter license key:")
        if not key:
            return
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            resp = requests.post(
                f"{API_URL}/api/license_check",
                headers=headers,
                json={"username": username, "license": key},
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("valid"):
                    messagebox.showinfo("License Check", "License is valid")
                else:
                    messagebox.showwarning("License Check", "License is invalid or expired")
            else:
                messagebox.showerror("Error", resp.text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def add_license(self):
        if not self.token:
            return
        item = self.clients_tree.selection()
        if not item:
            return
        username = self.clients_tree.item(item[0]).get("values")[0]
        key = simpledialog.askstring("Add License", "License key (blank to generate):")
        payload = {"username": username}
        if key:
            payload["license"] = key
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            resp = requests.post(f"{API_URL}/api/add_license", headers=headers, json=payload, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                messagebox.showinfo("Add License", f"License: {data.get('license')}")
            else:
                messagebox.showerror("Error", resp.text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def remove_license(self):
        if not self.token:
            return
        item = self.clients_tree.selection()
        if not item:
            return
        username = self.clients_tree.item(item[0]).get("values")[0]
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            resp = requests.post(
                f"{API_URL}/api/remove_license",
                headers=headers,
                json={"username": username},
                timeout=5,
            )
            if resp.status_code == 200:
                messagebox.showinfo("Remove License", "Removed")
            else:
                messagebox.showerror("Error", resp.text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def ban_hwid(self):
        if not self.token:
            return
        item = self.clients_tree.selection()
        if not item:
            return
        hwid = self.clients_tree.item(item[0]).get("values")[1]
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            resp = requests.post(
                f"{API_URL}/api/ban_hwid",
                headers=headers,
                json={"hwid": hwid},
                timeout=5,
            )
            if resp.status_code == 200:
                self.load_clients()
            else:
                messagebox.showerror("Error", resp.text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def create_license_check_ui(self):
        self.clear_root()
        frm = ttk.Frame(self.root, padding=20)
        frm.pack(expand=True)

        ttk.Label(frm, text="License Key").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.license_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.license_var, width=30).grid(row=0, column=1)

        ttk.Button(frm, text="Check License", command=self.license_check).grid(row=1, column=0, columnspan=2, pady=10)
        ttk.Button(frm, text="Back", command=self.create_main_ui).grid(row=2, column=0, columnspan=2)
        self.root.mainloop()

    def create_push_update_ui(self):
        self.clear_root()
        frm = ttk.Frame(self.root, padding=20)
        frm.pack(expand=True)

        ttk.Label(frm, text="New Version Tag").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.version_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.version_var, width=30).grid(row=0, column=1)

        ttk.Button(frm, text="Push Update", command=self.push_update).grid(row=1, column=0, columnspan=2, pady=10)
        ttk.Button(frm, text="Back", command=self.create_main_ui).grid(row=2, column=0, columnspan=2)
        self.root.mainloop()

    def push_update(self):
        if not self.token:
            return
        version = simpledialog.askstring("Push Update", "New version tag:")
        if not version:
            return
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            resp = requests.post(
                f"{API_URL}/api/set_version",
                headers=headers,
                json={"version": version},
                timeout=5,
            )
            if resp.status_code == 200:
                messagebox.showinfo("Success", "Version updated")
            else:
                messagebox.showerror("Error", resp.text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def toggle_ban(self):
        if not self.token:
            return
        item = self.clients_tree.selection()
        if not item:
            return
        values = self.clients_tree.item(item[0]).get("values")
        if not values:
            return
        username, hwid, banned = values[0], values[1], values[2]
        new_status = not banned
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            resp = requests.post(
                f"{API_URL}/api/set_banned",
                headers=headers,
                json={"username": username, "hwid": hwid, "banned": new_status},
                timeout=5,
            )
            if resp.status_code == 200:
                self.load_clients()
            else:
                messagebox.showerror("Error", resp.text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def remove_client(self):
        if not self.token:
            return
        item = self.clients_tree.selection()
        if not item:
            return
        values = self.clients_tree.item(item[0]).get("values")
        if not values:
            return
        username, hwid = values[0], values[1]
        if not messagebox.askyesno("Remove", f"Remove {username}?"):
            return
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            resp = requests.post(
                f"{API_URL}/api/remove_user",
                headers=headers,
                json={"username": username, "hwid": hwid},
                timeout=5,
            )
            if resp.status_code == 200:
                self.load_clients()
            else:
                messagebox.showerror("Error", resp.text)
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    EXDApp()
# This code is part of the EXD Developer Tool for FireGuard Antivirus.
# It provides a GUI for managing clients, logs, licenses, and updates.
# The tool allows administrators to log in, view client information, fetch logs,
# push updates, toggle bans, and manage licenses.
# The API_URL is set via environment variable or defaults to a public endpoint.
# The application uses ttkbootstrap for a modern look and feel.
# The main class EXDApp handles the UI and interactions with the API.
# The application is designed to be user-friendly and efficient for managing antivirus clients.
# The code is structured to allow easy expansion and modification for future features.
# The application is intended for use by administrators of the FireGuard Antivirus system.