import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
import re
import hashlib
import subprocess
import pefile
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import winsound
from plyer import notification
import ctypes
import psutil
import socket
import tempfile
import json

patterns = {
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

def run_in_real_sandbox(path):
    try:
        temp_dir = tempfile.mkdtemp(prefix="sandbox_")
        temp_path = os.path.join(temp_dir, os.path.basename(path))
        shutil.copy2(path, temp_path)
        p = subprocess.Popen([temp_path], creationflags=subprocess.CREATE_NEW_CONSOLE)
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

class FireGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🦠 FireGuard Antivirus")
        self.root.geometry("800x600")

        self.frame = ttk.Frame(self.root)
        self.frame.pack(fill="both", expand=True)

        self.text = ScrolledText(self.frame, wrap="word", bg="black", fg="lime", insertbackground="lime")
        self.text.pack(fill="both", expand=True)

        self.progress = ttk.Progressbar(self.root, mode="determinate")
        self.progress.pack(fill="x")

        self.toolbar = ttk.Frame(self.root)
        self.toolbar.pack(fill="x")

        ttk.Button(self.toolbar, text="📂 Otvoriť ZIP", command=self.open_zip).pack(side="left")
        ttk.Button(self.toolbar, text="📄 Skenovať súbor", command=self.scan_file).pack(side="left")
        ttk.Button(self.toolbar, text="🔍 Skenovať správanie", command=self.run_behavior).pack(side="left")
        ttk.Button(self.toolbar, text="🧪 Sandbox test", command=self.run_sandbox).pack(side="left")
        ttk.Button(self.toolbar, text="🟢 Real-Time sledovanie", command=self.toggle_monitoring).pack(side="left")
        ttk.Button(self.toolbar, text="🧹 Vyčistiť log", command=self.clear_log).pack(side="right")
        ttk.Button(self.toolbar, text="💾 Uložiť log", command=self.save_log).pack(side="right")

        self.monitoring = False
        self.observer = None

    def run_in_thread(self, func, *args):
        threading.Thread(target=func, args=args, daemon=True).start()

    def log(self, msg):
        self.text.insert("end", msg + "\n")
        self.text.see("end")
        print(msg)

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

    def scan_file(self):
        path = filedialog.askopenfilename(filetypes=[("Súbory", "*.*")])
        if path:
            self.run_in_thread(self.scan_directory, os.path.dirname(path))

    def clear_log(self):
        self.text.delete("1.0", tk.END)

    def save_log(self):
        log_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if log_path:
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(self.text.get("1.0", tk.END))

    def scan_directory(self, folder):
        files_to_scan = []
        if os.path.isfile(folder):
            files_to_scan.append(folder)
        else:
            for root, _, files in os.walk(folder):
                for file in files:
                    files_to_scan.append(os.path.join(root, file))

        total = len(files_to_scan)
        for idx, path in enumerate(files_to_scan, 1):
            file = os.path.basename(path)
            self.progress['maximum'] = total
            self.progress['value'] = idx
            if file.endswith(valid_ext):
                self.log(f"[•] Skenujem: {file}")
                with open(path, "rb") as f:
                    data = f.read()
                    content = data.decode("utf-8", errors="ignore")
                    score = calculate_threat_level(content)
                    md5 = hashlib.md5(data).hexdigest()
                    if score >= 3:
                        self.log(f"⚠️  Detegované podozrivé: {file} (Skóre: {score}) | MD5: {md5}")
                        notification.notify(title="FireGuard Alert", message=f"Hrozba: {file}", timeout=4)
                        winsound.Beep(1000, 400)
                if file.endswith(".exe"):
                    for line in analyze_exe_core(path):
                        self.log(line)
                    for line in deep_file_decompile(path):
                        if any(p in line.lower() for p in ['key', 'token', 'hack', 'inject']):
                            self.log(f"[DECOMP] {line.strip()}")
                if file.endswith(".dll"):
                    for line in analyze_exe_core(path):
                        self.log(line)
        self.progress['value'] = 0

    def run_behavior(self):
        self.log("[•] Spúšťam behaviorálnu analýzu...")
        for line in detect_behavior():
            self.log(line)

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
        else:
            self.observer.stop()
            self.observer.join()
            self.monitoring = False
            self.log("[•] Real-time monitoring ukončený.")

    def start_monitoring(self, folder):
        class Handler(FileSystemEventHandler):
            def on_created(self2, event):
                if event.is_directory:
                    return
                self.log(f"[!] Zistený nový súbor: {event.src_path}")
                self.run_in_thread(self.scan_directory, event.src_path)

        self.observer = Observer()
        self.observer.schedule(Handler(), folder, recursive=True)
        self.observer.start()

if __name__ == '__main__':
    root = tk.Tk()
    app = FireGuardApp(root)
    root.mainloop()
