import os
import shutil
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import ttkbootstrap as ttkb
from ttkbootstrap import ttk
import re
import hashlib
import subprocess
import pefile
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from concurrent.futures import ThreadPoolExecutor
try:
    import winsound

    def beep():
        winsound.Beep(1000, 400)
except Exception:  # pragma: no cover - winsound only on Windows
    def beep():
        print("\a", end="")

try:
    from plyer import notification
except Exception:
    notification = None
import ctypes
import psutil
import socket
import tempfile
import json
import requests
from packaging import version

VERSION = "0.1.0"
GITHUB_REPO = "TheMich157/-FireGuard-Antivirus"
LOG_PATH = "fireguard.log"
THREAT_THRESHOLD = 3
API_URL = os.environ.get("API_URL", "https://fireguard-antivirus.onrender.com")
LICENSE_FILE = "license.json"
TOKEN = None
USERNAME = None

def get_hwid() -> str:
    """Return a simple hardware ID based on MAC address."""
    try:
        import uuid
        return hashlib.md5(str(uuid.getnode()).encode()).hexdigest()
    except Exception:
        return "unknown"

HWID = get_hwid()


def load_token():
    global TOKEN, USERNAME
    try:
        with open(LICENSE_FILE, "r", encoding="utf-8") as f:
           data = json.load(f)
           TOKEN = data.get("token")
           USERNAME = data.get("username")
    except FileNotFoundError:
     TOKEN = None
     USERNAME = None

def save_token(token: str, username: str):
    global TOKEN, USERNAME
    TOKEN = token
    USERNAME = username
    try:
        with open(LICENSE_FILE, "w", encoding="utf-8") as f:
            json.dump({"token": token, "username": username}, f)
    except Exception:
        pass

def logout_user():
    """Clear stored token."""
    global TOKEN, USERNAME
    TOKEN = None
    USERNAME = None
    try:
        if os.path.exists(LICENSE_FILE):
            os.remove(LICENSE_FILE)
    except Exception:
        pass

def register_user(username: str, password: str) -> bool:
    r = api_post("/api/register", {"username": username, "password": password, "hwid": HWID})
    if isinstance(r, requests.Response) and r.ok:
        tok = r.json().get("token")
        if tok:
            save_token(tok, username)
            return True
    return False

def login_user(username: str, password: str) -> bool:
    r = api_post("/api/login", {"username": username, "password": password})
    if isinstance(r, requests.Response) and r.ok:
        tok = r.json().get("token")
        if tok:
            save_token(tok, username)
            return True
    return False

def api_post(endpoint: str, data: dict):
    """Helper to POST JSON data to the backend API."""
    headers = {}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    try:
        return requests.post(
            f"{API_URL}{endpoint}", json=data, headers=headers, timeout=5
        )
    except Exception:
        return None

def api_get(endpoint: str, params: dict | None = None):
    headers = {}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    try:
        return requests.get(
            f"{API_URL}{endpoint}", params=params, headers=headers, timeout=5
        )
    except Exception:
        return None

# Possible risks when using this program:
# - Running unknown files may damage your system.
# - Detection is not perfect and false positives can occur.
# - The sandbox cannot guarantee full isolation from malware.


# Keep a simple record of modules imported for logging purposes
IMPORTED_MODULES = [
    'os', 'shutil', 'tkinter', 'ttkbootstrap', 're', 'hashlib', 'subprocess',
    'pefile', 'time', 'threading', 'watchdog', 'winsound/beep', 'plyer',
    'ctypes', 'psutil', 'socket', 'tempfile', 'json', 'requests',
    'packaging.version'
]

# Supported interface languages
LANGUAGES = {
    'en': {
        'open_zip': 'Open ZIP',
        'scan_file': 'Scan File',
        'scan_dir': 'Scan Folder',
        'stop_scan': 'Stop Scan',
        'behavior_scan': 'Behavior Scan',
        'sandbox_test': 'Sandbox Test',
        'monitor': 'Real-Time Monitor',
        'clear_log': 'Clear Log',
        'save_log': 'Save Log',
        'save_patterns': 'Save Patterns',
        'open_quarantine': 'Open Quarantine',
        'scan_tab': 'Scanning',
        'settings_tab': 'Settings',
        'language': 'Language',
         'theme': 'Theme',
        'threads': 'Threads',
        'threshold': 'Threshold'
    },
    'sk': {
        'open_zip': 'Otvoriť ZIP',
        'scan_file': 'Skenovať súbor',
        'scan_dir': 'Skenovať priečinok',
        'stop_scan': 'Zastaviť scan',
        'behavior_scan': 'Sken správania',
        'sandbox_test': 'Sandbox test',
        'monitor': 'Real-Time sledovanie',
        'clear_log': 'Vyčistiť log',
        'save_log': 'Uložiť log',
        'save_patterns': 'Uložiť vzory',
        'open_quarantine': 'Otvoriť karanténu',
        'scan_tab': 'Skenovanie',
        'settings_tab': 'Nastavenia',
        'language': 'Jazyk',
        'theme': 'Téma',
        'threads': 'Vlákna',
        'threshold': 'Prah'
    },
    'cs': {
        'open_zip': 'Otevřít ZIP',
        'scan_file': 'Skenovat soubor',
        'scan_dir': 'Skenovat složku',
        'stop_scan': 'Zastavit sken',
        'behavior_scan': 'Sken chování',
        'sandbox_test': 'Sandbox test',
        'monitor': 'Sledování v reálném čase',
        'clear_log': 'Vymazat log',
        'save_log': 'Uložit log',
        'save_patterns': 'Uložit vzory',
        'open_quarantine': 'Otevřít karanténu',
        'scan_tab': 'Skenování',
        'settings_tab': 'Nastavení',
        'language': 'Jazyk',
        'theme': 'Téma',
        'threads': 'Vlákna',
        'threshold': 'Prahová hodnota'
    },
    'de': {
        'open_zip': 'ZIP öffnen',
        'scan_file': 'Datei scannen',
        'scan_dir': 'Ordner scannen',
        'stop_scan': 'Scan stoppen',
        'behavior_scan': 'Verhaltensscan',
        'sandbox_test': 'Sandbox-Test',
        'monitor': 'Echtzeitüberwachung',
        'clear_log': 'Log löschen',
        'save_log': 'Log speichern',
        'save_patterns': 'Muster speichern',
        'open_quarantine': 'Quarantäne öffnen',
        'scan_tab': 'Scan',
        'settings_tab': 'Einstellungen',
        'language': 'Sprache',
        'theme': 'Thema',
        'threads': 'Threads',
        'threshold': 'Schwelle'
    }
}

THEMES = {
    'light': 'flatly',
    'dark': 'darkly'
}


DEFAULT_PATTERNS = {
    r"loadstring": 5,
    r"getfenv": 4,
    r"setfenv": 4,
    r"game:HttpGet": 5,
    r"require\(.+http": 5,
    r"eval\(": 4,
    r"exec\(": 4,
    r"os\.system": 5,
    r"hookfunction": 5,
    r"debug\.getinfo": 5,
    r"WriteProcessMemory": 5,
    r"CreateRemoteThread": 5,
    r"VirtualAllocEx": 4,
    r"ShellExecute": 5,
    r"connect\(.*\)": 4,
    r"send\(.*\)": 4,
    r"recv\(.*\)": 4,
    r"[a-zA-Z0-9+/]{100,}={0,2}": 3,
    r"http[s]?://[^\s]+": 3,
    r"[0-9a-f]{80,}": 2,
    r"\.delete\(": 4,
    r"webhook|discord\.com/api/webhooks": 5
}

# these patterns can be customized at runtime via patterns.json
patterns = DEFAULT_PATTERNS.copy()

def load_patterns_from_file():
    if os.path.exists("patterns.json"):
        try:
            with open("patterns.json", "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_patterns_to_file(data):
    try:
        with open("patterns.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return True
    except Exception:
        return False

valid_ext = ('.lua', '.js', '.py', '.txt', '.json', '.bat', '.cmd', '.ps1', '.vbs', '.sh', '.exe', '.dll')

def check_7z_installed():
    from shutil import which
    if which("7z"):
        return "7z"
    for path in [r"C:\\Program Files\\7-Zip\\7z.exe", r"C:\\Program Files (x86)\\7-Zip\\7z.exe"]:
        if os.path.exists(path):
            return path
    return None

def extract_zip_7z(zip_path, extract_to):
    exe_path = check_7z_installed()
    if not exe_path:
        return False, "7z.exe nebol nájdený v systéme."
    try:
        result = subprocess.run(
            [exe_path, 'x', f'-o{extract_to}', zip_path, '-y'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.returncode != 0:
            return False, result.stderr.strip()
        return True, result.stdout.strip()
    except Exception as e:
        return False, str(e)

def analyze_exe_core(path):
    try:
        pe = pefile.PE(path)
        info = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    info.append(f"[EXE] Importuje: {imp.name.decode(errors='ignore')} z {entry.dll.decode(errors='ignore')}")
        return info
    except Exception as e:
        return [f"[!] Nepodarilo sa analyzovať .exe: {e}"]

def deep_file_decompile(path):
    try:
        result = subprocess.run(["strings", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        return [f"[!] Decompilačná chyba: {e}"]

def calculate_threat_level(content):
    score = 0
    for pattern, pts in patterns.items():
        if re.search(pattern, content):
            score += pts
    return score

def classify_score(score):
    if score >= 6:
        return "High"
    if score >= THREAT_THRESHOLD:
        return "Medium"
    return "Low"

def send_error_log(msg: str):
    api_post("/api/log_error", {"hwid": HWID, "error": msg})

def send_scan_report(file: str, level: str, score: int, md5: str):
    api_post(
        "/api/scan_report",
        {"hwid": HWID, "file": file, "level": level, "score": score, "md5": md5},
    )

def verify_integrity():
    """Send file hash to server and exit if tampered."""
    try:
        with open(__file__, "rb") as f:
            hash_ = hashlib.md5(f.read()).hexdigest()
        r = api_post("/api/verify_integrity", {"hwid": HWID, "hash": hash_})
        if isinstance(r, requests.Response) and r.ok:
            data = r.json()
            if data.get("tampered"):
                kill_switch("Integrity failure")
    except Exception:
        pass

def check_status():
    resp = api_get("/api/status", {"hwid": HWID})
    if resp is not None and resp.status_code == 200:
        data = resp.json()
        if data.get("banned"):
            reason = data.get("reason") or "User banned"
            kill_switch(reason)

def kill_switch(reason: str):
    api_post("/api/report_violation", {"hwid": HWID, "reason": reason})
    messagebox.showerror("FireGuard", f"Application disabled: {reason}")
    sys.exit(1)

def run_in_real_sandbox(path):
    try:
        temp_dir = tempfile.mkdtemp(prefix="sandbox_")
        temp_path = os.path.join(temp_dir, os.path.basename(path))
        shutil.copy2(path, temp_path)
        p = subprocess.Popen([temp_path])
        time.sleep(10)  # sandbox timeout
        if p.poll() is None:
            p.terminate()
        return f"[Sandbox] Súbor spustený a monitorovaný: {os.path.basename(path)}"
    except Exception as e:
        return f"[!] Sandbox chyba: {e}"

def detect_behavior():
    info = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            conns = proc.connections(kind='inet')
            for conn in conns:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    info.append(f"[BEHAVIOR] Proces {proc.info['name']} ({proc.info['pid']}) má spojenie na {conn.raddr.ip}:{conn.raddr.port}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return info

def scan_file_behavior(path):
    try:
        temp_dir = tempfile.mkdtemp(prefix="behavior_")
        temp_path = os.path.join(temp_dir, os.path.basename(path))
        shutil.copy2(path, temp_path)
        p = subprocess.Popen([temp_path])
        time.sleep(5)
        info = []
        try:
            proc = psutil.Process(p.pid)
            for conn in proc.connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    info.append(f"[BEHAVIOR] {proc.name()} -> {conn.raddr.ip}:{conn.raddr.port}")
        except psutil.Error:
            pass
        p.terminate()
        shutil.rmtree(temp_dir, ignore_errors=True)
        if info:
            return info
        return ["[✓] Žiadne podozrivé správanie nebolo zistené."]
    except Exception as e:
        return [f"[!] Chyba behaviorálneho skenu: {e}"]

class FireGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🦠 FireGuard Antivirus")
        self.root.geometry("800x600")
        self.style = ttkb.Style()
        self.lang = 'en'
        self.theme = 'flatly'
        self.style.theme_use(self.theme)
        check_status()
        verify_integrity()
        self.poll_status()
        icon_path = os.path.join(os.path.dirname(__file__), "fireguard_favicon.ico")

        if os.path.exists(icon_path):
            try:
                self.root.iconbitmap(icon_path)
            except Exception:
                try:
                    icon = tk.PhotoImage(file=icon_path)
                    self.root.iconphoto(True, icon)
                except Exception:
                    pass


        self.notebook = ttk.Notebook(self.root)
        self.scan_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        self.profile_tab = ttk.Frame(self.notebook)
        self.notebook.pack(fill="both", expand=True)
        self.notebook.add(self.scan_tab, text=LANGUAGES[self.lang]['scan_tab'])
        self.notebook.add(self.settings_tab, text=LANGUAGES[self.lang]['settings_tab'])
        self.notebook.add(self.profile_tab, text="Account")

        self.text = ScrolledText(self.scan_tab, wrap="word", bg="black", fg="lime", insertbackground="lime")
        self.text.pack(fill="both", expand=True)

        self.progress = ttk.Progressbar(self.scan_tab, mode="determinate")
        self.progress.pack(fill="x")

        self.toolbar = ttk.Frame(self.scan_tab)
        self.toolbar.pack(fill="x")

        self.pattern_text = ScrolledText(self.settings_tab, wrap="word")
        self.pattern_text.pack(fill="both", expand=True)
        self.save_patterns_btn = ttk.Button(
            self.settings_tab,
            text=LANGUAGES[self.lang]['save_patterns'],
            command=self.save_patterns
        )
        self.save_patterns_btn.pack()
        self.load_patterns_editor()

        controls = ttk.Frame(self.settings_tab)
        controls.pack(fill="x", pady=5)
        self.lbl_language = ttk.Label(controls, text=LANGUAGES[self.lang]['language'])
        self.lbl_language.pack(side="left")
        self.lang_var = tk.StringVar(value=self.lang)
        ttk.OptionMenu(controls, self.lang_var, self.lang, *LANGUAGES.keys(), command=self.change_language).pack(side="left", padx=5)
        self.lbl_theme = ttk.Label(controls, text=LANGUAGES[self.lang]['theme'])
        self.lbl_theme.pack(side="left", padx=20)
        self.theme_var = tk.StringVar(value='light')
        ttk.OptionMenu(controls, self.theme_var, 'light', 'light', 'dark', command=self.change_theme).pack(side="left")
        self.lbl_threads = ttk.Label(controls, text=LANGUAGES[self.lang]['threads'])
        self.lbl_threads.pack(side="left", padx=20)
        self.thread_var = tk.IntVar(value=max(1, os.cpu_count() or 4))
        ttk.Spinbox(controls, from_=1, to=16, textvariable=self.thread_var, width=3).pack(side="left")
        self.lbl_threshold = ttk.Label(controls, text=LANGUAGES[self.lang]['threshold'])
        self.lbl_threshold.pack(side="left", padx=20)
        self.threshold_var = tk.IntVar(value=THREAT_THRESHOLD)
        ttk.Spinbox(controls, from_=1, to=10, textvariable=self.threshold_var, width=3).pack(side="left")

        self.btn_open_zip = ttk.Button(self.toolbar, command=self.open_zip)
        self.btn_open_zip.pack(side="left")
        self.btn_scan_file = ttk.Button(self.toolbar, command=self.scan_file)
        self.btn_scan_file.pack(side="left")
        self.btn_scan_dir = ttk.Button(self.toolbar, command=self.scan_directory_prompt)
        self.btn_scan_dir.pack(side="left")
        self.btn_stop = ttk.Button(self.toolbar, command=self.stop_scan)
        self.btn_stop.pack(side="left")
        self.btn_behavior = ttk.Button(self.toolbar, command=self.run_behavior)
        self.btn_behavior.pack(side="left")
        self.btn_sandbox = ttk.Button(self.toolbar, command=self.run_sandbox)
        self.btn_sandbox.pack(side="left")
        self.btn_monitor = ttk.Button(self.toolbar, command=self.toggle_monitoring)
        self.btn_monitor.pack(side="left")
        self.btn_clear_log = ttk.Button(self.toolbar, command=self.clear_log)
        self.btn_clear_log.pack(side="right")
        self.btn_save_log = ttk.Button(self.toolbar, command=self.save_log)
        self.btn_save_log.pack(side="right")
        self.btn_update = ttk.Button(
        self.settings_tab,
         text="🔄 Check for Updates",
        command=self.check_for_updates_gui
        )
        self.btn_update.pack(pady=10)

        self.btn_open_quarantine = ttk.Button(self.toolbar, command=self.open_quarantine)
        self.btn_open_quarantine.pack(side="right")

        # account tab
        self.account_label = ttk.Label(self.profile_tab, text="")
        self.account_label.pack(pady=10)
        ttk.Button(self.profile_tab, text="Logout", command=self.logout_action).pack()

        self.apply_language()

        self.monitoring = False
        self.observer = None
        self.stop_event = threading.Event()
        patterns.update(load_patterns_from_file())
        self.log_imports()
        self.update_account_label()

    def authenticate(self):
        load_token()
        if TOKEN:
            self.update_account_label()
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("FireGuard Login")
        ttk.Label(dialog, text="Username").grid(row=0, column=0, pady=5, sticky=tk.W)
        user_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=user_var, width=30).grid(row=0, column=1)
        ttk.Label(dialog, text="Password").grid(row=1, column=0, pady=5, sticky=tk.W)
        pass_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=pass_var, show="*", width=30).grid(row=1, column=1)

        def do_login():
            if login_user(user_var.get(), pass_var.get()):
                dialog.destroy()
            else:
                messagebox.showerror("Login", "Failed to login")

        def do_register():
            if register_user(user_var.get(), pass_var.get()):
                messagebox.showinfo("Register", "Account created")
                dialog.destroy()
            else:
                messagebox.showerror("Register", "Registration failed")

        ttk.Button(dialog, text="Login", command=do_login).grid(row=2, column=0, pady=10)
        ttk.Button(dialog, text="Register", command=do_register).grid(row=2, column=1)
        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)
        self.update_account_label()

    def logout_action(self):
        if messagebox.askyesno("Logout", "Sign out from this device?"):
            logout_user()
            self.authenticate()

    def update_account_label(self):
        if USERNAME:
            self.account_label.config(text=f"Logged in as {USERNAME}")
        else:
            self.account_label.config(text="Not logged in")

    def check_for_updates_gui(self):
        try:
            url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
            r = requests.get(url, timeout=5)
            r.raise_for_status()
            data = r.json()
            latest = data.get("tag_name", "0.0.0").lstrip("v")
            if version.parse(latest) > version.parse(VERSION):
                if messagebox.askyesno(
                    "Update", f"New version {latest} is available. Download now?"
                ):
                    asset = next(
                        (a for a in data.get("assets", []) if a.get("name", "").endswith(".exe")),
                        None,
                    )
                    if asset:
                        dest = os.path.join(os.path.dirname(__file__), asset["name"])
                        with requests.get(asset["browser_download_url"], stream=True, timeout=10) as dl:
                            with open(dest, "wb") as f:
                                for chunk in dl.iter_content(1024 * 1024):
                                    if chunk:
                                        f.write(chunk)
                        messagebox.showinfo(
                            "Update", f"Downloaded {asset['name']}.\nPlease run it to update FireGuard."
                        )
            else:
                messagebox.showinfo("Up to Date", f"You already have the latest version ({VERSION}).")
        except Exception as e:
            messagebox.showerror("Update Error", f"Update check failed:\n{e}")

    def poll_status(self):
        try:
            check_status()
        finally:
            self.root.after(60000, self.poll_status)

    def run_in_thread(self, func, *args):
        def wrapper():
            try:
                func(*args)
            except Exception as e:
                send_error_log(str(e))
        threading.Thread(target=wrapper, daemon=True).start()



    def log(self, msg):
        self.text.insert("end", msg + "\n")
        self.text.see("end")
        print(msg)
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass
        send_scan_report("log", "info", 0, "") if msg else None

    def log_imports(self):
        self.log("[✓] Načítané moduly:")
        for name in IMPORTED_MODULES:
            self.log(f"  - {name}")

    def change_language(self, choice):
        self.lang = choice
        self.apply_language()

    def change_theme(self, choice):
        self.theme = THEMES.get(choice, 'flatly')
        self.style.theme_use(self.theme)


    def apply_language(self):
        t = LANGUAGES[self.lang]
        self.notebook.tab(0, text=t['scan_tab'])
        self.notebook.tab(1, text=t['settings_tab'])
        self.notebook.tab(2, text='Account')
        self.save_patterns_btn.config(text=t['save_patterns'])
        self.lbl_language.config(text=t['language'])
        self.lbl_theme.config(text=t['theme'])
        self.lbl_threads.config(text=t['threads'])
        self.lbl_threshold.config(text=t['threshold'])
        self.btn_open_zip.config(text='📂 ' + t['open_zip'])
        self.btn_scan_file.config(text='📄 ' + t['scan_file'])
        self.btn_scan_dir.config(text='📁 ' + t['scan_dir'])
        self.btn_stop.config(text='⏹ ' + t['stop_scan'])
        self.btn_behavior.config(text='🔍 ' + t['behavior_scan'])
        self.btn_sandbox.config(text='🧪 ' + t['sandbox_test'])
        self.btn_monitor.config(text='🟢 ' + t['monitor'])
        self.btn_clear_log.config(text='🧹 ' + t['clear_log'])
        self.btn_save_log.config(text='💾 ' + t['save_log'])
        self.btn_open_quarantine.config(text='📂 ' + t['open_quarantine'])

    def open_zip(self):
        zip_path = filedialog.askopenfilename(filetypes=[("ZIP súbory", "*.zip")])
        if not zip_path:
            return
        extract_to = os.path.join(os.getcwd(), "temp_extract")
        os.makedirs(extract_to, exist_ok=True)

        success, output = extract_zip_7z(zip_path, extract_to)
        if success:
            self.log("[✓] Archív extrahovaný pomocou 7-Zip.")
            self.run_in_thread(self.scan_directory, extract_to)
        else:
            self.log(f"[ERROR] Extrakcia zlyhala: {output}")
            send_error_log(output)

    def scan_file(self):
        path = filedialog.askopenfilename(filetypes=[("Súbory", "*.*")])
        if path:
            self.run_in_thread(self.scan_directory, path)

    def scan_directory_prompt(self):
        folder = filedialog.askdirectory()
        if folder:
            self.run_in_thread(self.scan_directory, folder)

    def stop_scan(self):
        self.stop_event.set()

    def load_patterns_editor(self):
        content = json.dumps(patterns, indent=4, ensure_ascii=False)
        self.pattern_text.delete("1.0", tk.END)
        self.pattern_text.insert("1.0", content)

    def save_patterns(self):
        try:
            data = json.loads(self.pattern_text.get("1.0", tk.END))
            patterns.clear()
            patterns.update(data)
            save_patterns_to_file(patterns)
            messagebox.showinfo("Vzory", "Vzory uložené.")
        except Exception as e:
            messagebox.showerror("Vzory", f"Chyba: {e}")
            send_error_log(str(e))

    def clear_log(self):
        self.text.delete("1.0", tk.END)

    def save_log(self):
        log_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if log_path:
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(self.text.get("1.0", tk.END))

    def open_quarantine(self):
        qdir = os.path.join(os.getcwd(), "quarantine")
        os.makedirs(qdir, exist_ok=True)
        try:
            if os.name == 'nt':
                os.startfile(qdir)
            else:
              subprocess.Popen(['xdg-open', qdir])
        except Exception:
            messagebox.showinfo('Quarantine', qdir)
            send_error_log('open_quarantine_failed')

    def scan_single(self, path):
        file = os.path.basename(path)
        if not file.endswith(valid_ext):
            return
        self.log(f"[•] Skenujem: {file}")
        with open(path, "rb") as f:
            data = f.read()
        content = data.decode("utf-8", errors="ignore")
        score = calculate_threat_level(content)
        md5 = hashlib.md5(data).hexdigest()
        if score >= self.threshold_var.get():
            level = classify_score(score)
            self.log(f"⚠️  Detegované podozrivé: {file} (Level: {level}, Score: {score}) | MD5: {md5}")
            if notification:
                notification.notify(title="FireGuard Alert", message=f"Hrozba: {file}", timeout=4)
            beep()
            if messagebox.askyesno("Quarantine", f"Presunúť {file} do karantény?"):
                qdir = os.path.join(os.getcwd(), "quarantine")
                os.makedirs(qdir, exist_ok=True)
                shutil.move(path, os.path.join(qdir, file))
                send_scan_report(file, level, score, md5)
                return
            send_scan_report(file, level, score, md5)
        else:
            send_scan_report(file, "Clean", score, md5)
        if file.endswith(".exe") or file.endswith(".dll"):
            for line in analyze_exe_core(path):
                self.log(line)
        if file.endswith(".exe"):
            for line in deep_file_decompile(path):
                if any(p in line.lower() for p in ['key', 'token', 'hack', 'inject']):
                    self.log(f"[DECOMP] {line.strip()}")

    def scan_directory(self, folder):
        self.stop_event.clear()
        files_to_scan = []
        if os.path.isfile(folder):
            files_to_scan.append(folder)
        else:
            for root, _, files in os.walk(folder):
                for file in files:
                    files_to_scan.append(os.path.join(root, file))

        total = len(files_to_scan)
        self.progress['maximum'] = total
        with ThreadPoolExecutor(max_workers=self.thread_var.get()) as ex:
            futures = []
            for path in files_to_scan:
                if self.stop_event.is_set():
                    break
                futures.append(ex.submit(self.scan_single, path))
            for idx, fut in enumerate(futures, 1):
                fut.result()
                self.progress['value'] = idx
        self.progress['value'] = 0

    def run_behavior(self):
        path = filedialog.askopenfilename(filetypes=[("Executable", "*.exe"), ("All files", "*.*")])
        if not path:
            return
        self.log(f"[•] Skenovanie správania súboru: {os.path.basename(path)}")
        self.run_in_thread(self._behavior_task, path)

    def _behavior_task(self, path):
        for line in scan_file_behavior(path):
            self.log(line)
            send_scan_report(os.path.basename(path), "behavior", 0, "")

    def run_sandbox(self):
        path = filedialog.askopenfilename(filetypes=[("Executable", "*.exe")])
        if path:
            self.log(run_in_real_sandbox(path))

    def toggle_monitoring(self):
        if not self.monitoring:
            folder = filedialog.askdirectory()
            if folder:
                self.monitoring = True
                self.log(f"[✓] Spustený real-time monitoring priečinka: {folder}")
                self.start_monitoring(folder)
                send_scan_report("monitor", "start", 0, "")
        else:
            self.observer.stop()
            self.observer.join()
            self.monitoring = False
            self.log("[•] Real-time monitoring ukončený.")
            send_scan_report("monitor", "stop", 0, "")

    def start_monitoring(self, folder):
        class Handler(FileSystemEventHandler):
            def on_created(self2, event):
                if event.is_directory:
                    return
                self.log(f"[!] Zistený nový súbor: {event.src_path}")
                self.run_in_thread(self.scan_single, event.src_path)
                send_scan_report("monitor", "created", 0, "")

        self.observer = Observer()
        self.observer.schedule(Handler(), folder, recursive=True)

        self.observer.start()

if __name__ == '__main__':
 app = FireGuardApp(ttkb.Window())
 app.check_for_updates_gui()
 app.root.mainloop()
