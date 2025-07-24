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
  - Alerts user with popups and an optional beep when threats are detected.
- 📝 **Import Log**
  - On startup the log shows all Python modules successfully loaded.
- 🎨 **Light & Dark Themes**
  - Switch between modern light or dark appearances.
- 🌐 **Multi-language UI**
  - Interface available in English, Slovak, Czech and German.
- 📂 **Open Quarantine Folder**
  - Quickly review quarantined files from the toolbar.
  - 🔀 **Threaded Scanning**
  - Uses multiple worker threads for faster scans.
- ⚙️ **Adjustable Detection Threshold**
  - Choose how sensitive the scanner is to suspicious patterns.
- 📊 **Threat Level Classification**
  - Results show Low/Medium/High severity ratings.
- 📜 **Automatic Log File**
  - All events are stored in `fireguard.log`.
- 🪪 **MD5 Hash Display**
  - Every scan shows the MD5 of each file.
- 🧹 **Quarantine Management**
  - Automatically move threats to the quarantine folder.
- 📝 **Save & Clear Log**
  - Manage the log directly from the toolbar.
- 📡 **Network Behavior Viewer**
  - View active network connections during behavior scans.
- 🎚 **Adjustable Thread Count**
  - Set how many threads to use for scanning.
- 🕒 **Progress Bar Indicator**
  - Visual progress updates during long scans.
- 🧩 **Settings Tab**
  - Edit patterns and options in one place.
- 🌁 **Modern ttkbootstrap UI**
  - Clean look & feel with dark and light themes.
- 🖱 **Drag & Drop Files**
  - Drop files onto the window to start an immediate scan.

---

## 🚀 How to Run

1. **Install Dependencies**

```bash
pip install pefile watchdog psutil plyer ttkbootstrap
```

2. **Run the application**

```bash
python fireguard.py
```

The modern interface (powered by **ttkbootstrap**) now contains two tabs: **Skenovanie** for running scans and **Nastavenia** for editing detection patterns. Use the toolbar buttons to scan files or directories, stop a running scan, request a behavior scan of a single file, open the quarantine folder, and save or clear the log. Choose your theme, language, thread count, and detection threshold in the settings tab.
If a `fireguard.ico` is present, it becomes the window icon.

### Build a Windows EXE

Install [PyInstaller](https://pyinstaller.org/) and generate a single-file executable:

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole fireguard.py
```

The compiled `fireguard.exe` automatically checks GitHub releases on startup and prompts to download a newer version if available.

### Account Login

FireGuard now requires users to create a free account. On first launch you will
be prompted to register or log in. After successful authentication a license
token is stored locally and used for all API communication.

### Developer Tool EXD

The EXD developer tool allows administrators to log in and monitor client activity.
To run it locally:

```bash
python exd.py
```

The tool communicates with the backend API and requires valid admin credentials.


### Backend API Deployment

A simple Flask API implementation is provided in `server.py`. You can deploy it to [Render](https://render.com) using the included `render.yaml` configuration:

```bash
pip install -r requirements.txt
python server.py  # local testing
```
On Render, create a new Web Service from this repo and it will automatically use `gunicorn server:app` to start the API.

Key admin endpoints include:

- `GET /api/clients` – list all registered users
- `POST /api/remove_user` – delete a user account
- `POST /api/set_version` – update the latest client version
- `GET /api/logs` – fetch logs (optionally by `hwid`)
- `POST /api/set_banned` – ban or unban a client
- `POST /api/ban` – ban with reason
- `POST /api/unban` – remove a ban
- `POST /api/unlink_hwid` – reset a user's HWID
- `POST /api/security/kill_switch` – force shutdown on a client
- `POST /api/security/flag_hwid` – mark hardware ID as suspicious
- `GET /api/activity_log` – view admin activity history
- `GET /api/version_history` – list all versions
- `GET /api/download_update` – download the latest binary
- `POST /api/change_password` – user changes their password
- `GET /api/me` – current user info
- `POST /api/logout` – logout current token
- `POST /api/reset_password_request` – create password reset token
- `POST /api/reset_password` – complete password reset
- `POST /api/refresh_token` – issue new JWT
- `GET /api/stats` – basic usage stats
- `POST /api/inbox/send` – send a message to a user
- `GET /api/inbox` – list inbox messages
- `POST /api/inbox/read/<id>` – mark message read
- `GET /api/violations` – list logged violations
- `GET /api/logs/errors` – only error logs
- `POST /api/analyze_file` – upload a file for scoring
- `GET /api/get_threat_score/<md5>` – query score by hash
- `POST /api/submit_feedback` – user submits feedback
- Visit `/admin` in a browser to access a simple dashboard showing endpoint health and user count (login with your EXD credentials).
