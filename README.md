# 🦠 FireGuard Antivirus

FireGuard Antivirus is a Python desktop application that performs static and behavioral malware analysis. A small Flask backend manages user accounts, logs, and version updates. An optional developer tool (**EXD**) lets admins review clients, push updates and inspect logs.

You can try the hosted API at [wsl-agjq.onrender.com](https://wsl-agjq.onrender.com/).

---

## Features
- **Pattern Detection** – regex based scanning of scripts and executables
- **Executable Analysis** – inspect imports of `.exe`/`.dll` files
- **ZIP Extraction** – analyze archives using 7‑Zip
- **Sandbox Execution** – run suspicious files in a temporary folder
- **Real‑Time Monitoring** – watch directories for new files
- **Behavior Scanner** – check running processes for suspicious network activity
- **Notifications** – desktop popups and optional sound alerts
- **Quarantine** – isolate infected files
- **Multi‑language UI** – English, Slovak, Czech and German
- **Modern ttkbootstrap interface** with light and dark themes

---

## Quick Start
1. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```
2. Launch the client
   ```bash
   python fireguard.py
   ```
   The first run asks you to register or log in. Credentials are stored in `license.json` and used for all API calls.

### Building a Windows executable
```bash
pip install pyinstaller
pyinstaller --onefile --noconsole fireguard.py
```

Set `API_URL` to point the client to your backend:
```bash
API_URL=https://myserver.com python fireguard.py
```

---

## Server Setup
1. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```
2. Environment variables:
   - `MONGO_URI` – MongoDB connection URI
   - `MONGO_DB_NAME` – database name (default `FireGuard`)
   - `SECRET_KEY` – Flask secret for JWTs
   - `ADMIN_PASS` – initial admin password
   - `LATEST_VERSION` – current client version tag
  - `LATEST_BINARY` – path to the latest `.exe` served via `/release` (auth required)
3. Start locally with:
   ```bash
   python server.py
   ```
   or in production:
   ```bash
   gunicorn server:app
   ```

A minimal configuration for Render is provided in `render.yaml`.

---

## Developer Tool (EXD)
Run `python exd.py` to launch the admin toolkit. After logging in you can:
- View registered clients and their HWIDs
- Push a new client version
- Toggle bans or remove users
- Browse logs in real time

EXD is distributed under the same MIT License as the rest of FireGuard. You may
share the compiled `exd.exe` freely as long as the license file is included. This free management tool lets you oversee client registrations and push new versions.

---

## Admin Dashboard
The backend exposes `/admin` – a simple page listing API routes with a green/red status indicator and the total user count. Use your EXD credentials to log in.

### Built-in API docs
Browse `/docs` on the server to view styled pages for each API endpoint. Subpages describe the method and purpose of the route and link directly to the live API.

The landing page at `/` now contains a small HTML/JavaScript interface for registering or logging in using the API. Successful requests show the returned token on screen. The page and the built‑in docs use a cleaner theme for easier navigation.

---

## API Overview
| Route | Description |
| ----- | ----------- |
| `POST /api/register` | create a new account |
| `POST /api/login` | authenticate user |
| `GET /api/me` | return current account info |
| `POST /api/change_password` | change logged in user's password |
| `POST /api/logout` | invalidate token (optional) |
| `POST /api/reset_password_request` | start a password reset |
| `POST /api/reset_password` | complete password reset |
| `POST /api/refresh_token` | renew JWT |
| `GET /api/check_update` | get latest client version |
| `POST /api/set_version` | set latest version (admin) |
| `GET /api/download_update` | download newest binary *(auth required)* |
| `GET /release` | direct binary download *(auth required)* |
| `GET /api/version_history` | list previous versions |
| `GET /api/clients` | list all users (admin) |
| `POST /api/remove_user` | delete an account |
| `POST /api/ban` | ban a user or HWID |
| `POST /api/unban` | remove a ban |
| `POST /api/set_banned` | toggle ban status |
| `POST /api/unlink_hwid` | reset user's HWID |
| `POST /api/security/kill_switch` | force shutdown on a client |
| `POST /api/security/flag_hwid` | mark HWID as suspicious |
| `GET /api/activity_log` | admin activity history |
| `GET /api/logs` | fetch logs (optionally by HWID) |
| `GET /api/logs/errors` | fetch only error logs |
| `GET /api/stats` | system statistics |
| `GET /api/violations` | list reported violations |
| `POST /api/inbox/send` | send message to user |
| `GET /api/inbox` | list inbox messages |
| `POST /api/inbox/read/<id>` | mark message as read |
| `POST /api/analyze_file` | upload file for scoring |
| `GET /api/get_threat_score/<md5>` | query score by hash |
| `POST /api/submit_feedback` | submit false‑positive feedback |

Every endpoint requires a `Bearer` token header except `/admin` and the registration/login routes.

---

FireGuard is a work in progress and should not be trusted as a full security solution. Use it for educational purposes only.

## License
This project is released under the MIT License. See [LICENSE](LICENSE) for details.
