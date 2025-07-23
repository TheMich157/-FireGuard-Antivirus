import os
import shutil
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
import winsound
from plyer import notification
import ctypes
import psutil
import socket
import tempfile
import json

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

        self.notebook = ttk.Notebook(self.root)
        self.scan_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.pack(fill="both", expand=True)
        self.notebook.add(self.scan_tab, text="Skenovanie")
        self.notebook.add(self.settings_tab, text="Nastavenia")

        self.text = ScrolledText(self.scan_tab, wrap="word", bg="black", fg="lime", insertbackground="lime")
        self.text.pack(fill="both", expand=True)

        self.progress = ttk.Progressbar(self.scan_tab, mode="determinate")
        self.progress.pack(fill="x")

        self.toolbar = ttk.Frame(self.scan_tab)
        self.toolbar.pack(fill="x")

        self.pattern_text = ScrolledText(self.settings_tab, wrap="word")
        self.pattern_text.pack(fill="both", expand=True)
        ttk.Button(self.settings_tab, text="Uložiť vzory", command=self.save_patterns).pack()
        self.load_patterns_editor()

        ttk.Button(self.toolbar, text="📂 Otvoriť ZIP", command=self.open_zip).pack(side="left")
        ttk.Button(self.toolbar, text="📄 Skenovať súbor", command=self.scan_file).pack(side="left")
        ttk.Button(self.toolbar, text="📁 Skenovať priečinok", command=self.scan_directory_prompt).pack(side="left")
        ttk.Button(self.toolbar, text="⏹ Zastaviť scan", command=self.stop_scan).pack(side="left")
        ttk.Button(self.toolbar, text="🔍 Skenovať správanie", command=self.run_behavior).pack(side="left")
        ttk.Button(self.toolbar, text="🧪 Sandbox test", command=self.run_sandbox).pack(side="left")
        ttk.Button(self.toolbar, text="🟢 Real-Time sledovanie", command=self.toggle_monitoring).pack(side="left")
        ttk.Button(self.toolbar, text="🧹 Vyčistiť log", command=self.clear_log).pack(side="right")
        ttk.Button(self.toolbar, text="💾 Uložiť log", command=self.save_log).pack(side="right")

        self.monitoring = False
        self.observer = None
        self.stop_event = threading.Event()
        patterns.update(load_patterns_from_file())

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

    def clear_log(self):
        self.text.delete("1.0", tk.END)

    def save_log(self):
        log_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if log_path:
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(self.text.get("1.0", tk.END))

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
        for idx, path in enumerate(files_to_scan, 1):
            if self.stop_event.is_set():
                break
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
                        if messagebox.askyesno("Quarantine", f"Presunúť {file} do karantény?"):
                            qdir = os.path.join(os.getcwd(), "quarantine")
                            os.makedirs(qdir, exist_ok=True)
                            shutil.move(path, os.path.join(qdir, file))
                            continue
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
        path = filedialog.askopenfilename(filetypes=[("Executable", "*.exe"), ("All files", "*.*")])
        if not path:
            return
        self.log(f"[•] Skenovanie správania súboru: {os.path.basename(path)}")
        self.run_in_thread(self._behavior_task, path)

    def _behavior_task(self, path):
        for line in scan_file_behavior(path):
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
    root = ttkb.Window(themename="flatly")
    app = FireGuardApp(root)
    root.mainloop()
