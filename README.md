# 🦠 FireGuard Antivirus

**FireGuard Antivirus** is a powerful real-time desktop application built in Python with a Tkinter GUI. It provides static and behavioral analysis of files (especially `.exe`, scripts, and zip archives), detects malware patterns, scans behavioral anomalies, and even runs files in a real sandboxed environment.

---

## 📦 Features

- 🔍 **Pattern-Based Threat Detection**
  - Scans code/scripts for known malicious patterns using regex scoring.
- 🧪 **Executable File Analysis**
  - Analyzes `.exe` and `.dll` imports via `pefile`.
  - Decompiles binaries using `strings` for deep inspection.
- 📂 **ZIP File Extraction & Scan**
  - Uses `7-Zip` to extract and analyze ZIP files for threats.
- 📁 **Directory & File Scanning**
  - Scan entire folders or individual files with progress feedback.
- 🛑 **Stop Scans Anytime**
  - Abort long scans with the stop button.
- 📄 **Editable Detection Patterns**
  - Customize regex rules via `patterns.json` in the settings tab.
- 🔬 **Sandbox Execution**
  - Launch `.exe` files in a real temporary sandbox for safe observation.
- 🛜 **Behavioral Analysis**
  - Detects active network connections of running processes.
- 🔄 **Real-Time Directory Monitoring**
  - Detects new files and scans them on the fly.
- 🩺 **Behavior Scan on Demand**
  - Runs a selected executable in a sandbox and reports suspicious network activity.
- 📢 **Desktop Notifications & Audio Alerts**
  - Alerts user with sound and popups when threats are detected.

---

## 🚀 How to Run

1. **Install Dependencies**

```bash

pip install pefile watchdog psutil plyer ttkbootstrap
=======
pip install pefile watchdog psutil plyer

```

2. **Run the application**

```bash
python fireguard.py
```

The modern interface (powered by **ttkbootstrap**) now contains two tabs: **Skenovanie** for running scans and **Nastavenia** for editing detection patterns. Use the toolbar buttons to scan files or directories, stop a running scan, request a behavior scan of a single file, and save or clear the log. Any suspicious files can be quarantined automatically.
=======
The interface now includes quick actions for scanning individual files, clearing logs and saving reports. Progress of scans is displayed via a progress bar so you know how far along a scan is.

