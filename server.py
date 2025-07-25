from flask import (
    Flask,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    render_template_string,
)
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_file
import hashlib
import jwt
import datetime
import os
from functools import wraps
import threading
import time
import requests
import uuid
import sys

# Simple CSS style used by rendered pages
STYLE = """
<style>
body {
    font-family: 'Segoe UI', Tahoma, sans-serif;
    background: linear-gradient(#fff, #e3ebf3);
    color: #222;
    max-inline-size: 900px;
    margin: 40px auto;
    padding: 20px;
}
h1 {color:#dc3545;}
h2 {color:#0275d8;}
table {
    border-collapse: collapse;
    inline-size: 100%;
    background:#fff;
    border-radius:4px;
    box-shadow:0 2px 4px rgba(0,0,0,0.1);
}
th {background:#f7f7f7; text-align:start;}
tr:nth-child(odd) {background:#fbfbfb;}
th, td {padding:8px 12px; border-block-end:1px solid #ddd;}
button {
    background:#dc3545; color:#fff; border:none;
    padding:8px 14px; border-radius:4px; cursor:pointer;
}
button:hover {background:#c9302c;}
input {
    padding:6px 8px; margin-block-end:10px; inline-size:100%;
    border:1px solid #ccc; border-radius:4px;
}
.container {max-inline-size:800px;margin:auto;}
.card {
    padding:15px; background:#fff; border-radius:4px;
    box-shadow:0 2px 4px rgba(0,0,0,0.1); margin-block-end:20px;
}
</style>
"""

# Basic info for the API documentation pages
API_DOCS = {
    '/api/register': ('POST', 'create a new account'),
    '/api/login': ('POST', 'authenticate user'),
    '/api/me': ('GET', 'return current account info'),
    '/api/change_password': ('POST', "change logged in user's password"),
    '/api/reset_password_request': ('POST', 'start a password reset'),
    '/api/reset_password': ('POST', 'complete password reset'),
    '/api/check_update': ('GET', 'get latest client version'),
    '/api/set_version': ('POST', 'set latest version (admin)'),
    '/api/download_update': ('GET', 'download newest binary'),
    '/release': ('GET', 'direct binary download'),
    '/api/download_update': ('GET', 'download newest binary (auth)'),
    '/release': ('GET', 'direct binary download (auth)'),
    '/api/version_history': ('GET', 'list previous versions'),
    '/api/clients': ('GET', 'list all users (admin)'),
    '/api/remove_user': ('POST', 'delete an account'),
     '/api/ban': ('POST', 'ban a user or HWID'),
    '/api/unban': ('POST', 'remove a ban'),
    '/api/ban_hwid': ('POST', 'ban by HWID'),
    '/api/set_banned': ('POST', 'toggle ban status'),
    '/api/unlink_hwid': ('POST', "reset user's HWID"),
    '/api/add_license': ('POST', 'assign license key'),
    '/api/remove_license': ('POST', 'delete license'),
    '/api/license_check': ('POST', 'verify license key'),
    '/api/my_license': ('GET', 'return current license info'),
    '/api/find_username': ('POST', 'lookup username by license or HWID'),
    '/api/security/kill_switch': ('POST', 'force shutdown on a client'),
    '/api/security/flag_hwid': ('POST', 'mark HWID as suspicious'),
    '/api/activity_log': ('GET', 'admin activity history'),
    '/api/logs': ('GET', 'fetch logs'),
    '/api/logs/errors': ('GET', 'fetch only error logs'),
    '/api/stats': ('GET', 'system statistics'),
    '/api/violations': ('GET', 'list reported violations'),
    '/api/inbox/send': ('POST', 'send message to user'),
    '/api/inbox': ('GET', 'list inbox messages'),
    '/api/inbox/read/<id>': ('POST', 'mark message as read'),
    '/api/analyze_file': ('POST', 'upload file for scoring'),
    '/api/get_threat_score/<md5>': ('GET', 'query score by hash'),
    '/api/submit_feedback': ('POST', 'submit false-positive feedback'),
    '/api/control/restart': ('POST', 'restart the server (admin)'),
    '/api/control/shutdown': ('POST', 'shutdown the server (admin)'),
}

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dwdhwuhdkwhudkwdhwudhwuhd')
MONGO_URI = os.environ.get(
    'MONGO_URI',
    'mongodb+srv://admin:admin@cluster0.wp3kmd1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'
)
DB_NAME = os.environ.get('MONGO_DB_NAME', 'FireGuard')
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
db = client[DB_NAME]
if not client.server_info():
    raise Exception("MongoDB connection failed. Check your MONGO_URI.")

PING_URL = os.environ.get('PING_URL')
PING_INTERVAL = int(os.environ.get('PING_INTERVAL', '600'))
DISCORD_BOT_TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
DISCORD_CHANNEL_ID = os.environ.get('DISCORD_CHANNEL_ID')

# Collections

users = db['users']
logs = db['logs']
scans = db['scans']
violations = db['violations']
versions = db['versions']
messages = db['messages']
feedback = db['feedback']
activity = db['activity']
flags = db['flags']
reset_tokens = db['reset_tokens']

def init_db():
    users.create_index('username', unique=True)
    users.create_index('hwid', unique=True, sparse=True)
    messages.create_index('user_id')
    versions.create_index('version', unique=True)
    reset_tokens.create_index('token', unique=True, sparse=True)
    activity.create_index('ts')
    if not users.find_one({'username': 'admin'}):
        admin_pass = os.environ.get('ADMIN_PASS', 'admin')
        hashed = generate_password_hash(admin_pass)
        users.insert_one({'username': 'admin', 'password': hashed, 'role': 'admin', 'banned': False})
    if versions.count_documents({}) == 0:
        versions.insert_one({'version': LATEST_VERSION, 'ts': datetime.datetime.utcnow()})

LATEST_VERSION = os.environ.get('LATEST_VERSION', '0.3.1')

# Ensure the database is initialized
if not client.server_info():
    raise Exception("MongoDB connection failed. Check your MONGO_URI.")
# Initialize the database
init_db()

# Auto-ping functionality to keep the service awake
def start_autoping():
    """Periodically ping the given URL to keep the service awake."""
    if not PING_URL:
        return

    def _loop():
        while True:
            try:
                requests.get(PING_URL, timeout=10)
            except Exception:
                pass
            time.sleep(PING_INTERVAL)

    threading.Thread(target=_loop, daemon=True).start()

start_autoping()

# API URL
API_URL = os.environ.get("API_URL", "https://fireguard.aigenres.xyz")



def log_activity(user_id, action, info=None):
    """Record an admin or user action."""
    try:
        activity.insert_one({
            'user_id': str(user_id),
            'action': action,
            'info': info,
            'ts': datetime.datetime.utcnow(),
        })
    except Exception:
           pass


def send_license_discord(username: str, license_key: str) -> None:
    """Notify Discord when a new license is generated using a bot."""
    if not DISCORD_BOT_TOKEN or not DISCORD_CHANNEL_ID:
        return
    try:
        requests.post(
            f"https://discord.com/api/v10/channels/{DISCORD_CHANNEL_ID}/messages",
            headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            json={"content": f"New license for {username}: `{license_key}`"},
            timeout=5,
        )
    except Exception:
        pass

def auth_required(f):
    """Require a valid license key via the ``X-License`` header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get('X-Admin') == '1' and session.get('admin'):
            request.user_id = session['admin']
            return f(*args, **kwargs)
        key = request.headers.get('X-License')
        if not key:
            return jsonify({'error': 'missing license'}), 401
        user = users.find_one({'license': key})
        if not user:
            return jsonify({'error': 'invalid license'}), 403
        request.user_id = str(user['_id'])
        return f(*args, **kwargs)
    return decorated


def admin_login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)

    return wrapped


def admin_required(f):
    """Ensure the authenticated user has admin role."""
    @auth_required
    @wraps(f)
    def decorated(*args, **kwargs):
        user = users.find_one({'_id': ObjectId(request.user_id)})
        if not user or user.get('role') != 'admin':
            return jsonify({'error': 'admin only'}), 403
        return f(*args, **kwargs)

    return decorated


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = ''
    if request.method == 'POST':
        user = users.find_one({'username': request.form.get('username')})
        if (
            user
            and check_password_hash(user['password'], request.form.get('password', ''))
            and user.get('role') == 'admin'
        ):
            session['admin'] = str(user['_id'])
            return redirect(url_for('admin_dashboard'))
        error = 'Invalid credentials'
    return render_template_string(
        STYLE + '''<form method="post" class="container" style="max-inline-size:300px;">
            <h2>Admin Login</h2>
            <p style="color:red;">{{error}}</p>
            <input name="username" placeholder="Username" style="inline-size:100%;margin-block-end:10px;">
            <input name="password" type="password" placeholder="Password" style="inline-size:100%;margin-block-end:10px;">
            <button type="submit">Login</button>
        </form>''',
        error=error,
    )


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

LANDING_PAGE = """
<!doctype html>
<html>
<head>
    <title>FireGuard Antivirus</title>

</head>
<body class="container">
    <h1>FireGuard Antivirus</h1>
    <p id="status"></p>
    <div class="card">
        <h2>Register</h2>
        <input id="reg_user" placeholder="Username">
        <input id="reg_pass" type="password" placeholder="Password">
        <button onclick="register()">Register</button>

        <h2>Login</h2>
        <input id="log_user" placeholder="Username">
        <input id="log_pass" type="password" placeholder="Password">
        <button onclick="login()">Login</button>
    </div>
    <p>API reference: <a href='/docs'>/docs</a> | <a href='/admin'>Admin</a></p>
<script>
async function register(){
    const res = await fetch('/api/register', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username:document.getElementById('reg_user').value, password:document.getElementById('reg_pass').value})});
    const data = await res.json();
    document.getElementById('status').innerText = data.license ? 'Registered! License: '+data.license : (data.error||'Error');
}
async function login(){
    const res = await fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username:document.getElementById('log_user').value, password:document.getElementById('log_pass').value})});
    const data = await res.json();
    document.getElementById('status').innerText = data.license ? 'Logged in! License: '+data.license : (data.error||'Error');
}
</script>
</body>
</html>
"""


@app.route('/')
def home_page():
    """Interactive landing page with register/login forms."""
    return render_template_string(STYLE + LANDING_PAGE)

@app.route('/docs')
def docs_index():
    """List available API endpoints."""
    rows = []
    for path, (method, desc) in sorted(API_DOCS.items()):
            rows.append(
            f"<tr><td><a href='/docs{path}'>{path}</a></td><td>{method}</td><td>{desc}</td></tr>"
        )
    table = "<table><tr><th>Endpoint</th><th>Method</th><th>Description</th></tr>" + "".join(rows) + "</table>"
    html = f"<div class='container'><h2>API Documentation</h2>{table}</div>"
    return render_template_string(STYLE + html)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_page():
    """Simple interface for requesting and completing a password reset."""
    msg = ''
    if request.method == 'POST':
        if request.form.get('action') == 'request':
            user = request.form.get('username')
            with app.test_client() as c:
                resp = c.post('/api/reset_password_request', json={'username': user})
                if resp.status_code == 200:
                    msg = 'Token: ' + resp.json.get('token', '')
                else:
                    msg = resp.json.get('error', '')
        else:
            token = request.form.get('token')
            new = request.form.get('new_password')
            with app.test_client() as c:
                resp = c.post('/api/reset_password', json={'token': token, 'new_password': new})
                msg = resp.json.get('status') or resp.json.get('error', '')
    html = (
        "<div class='container'><h2>Password Reset</h2>"
        f"<p>{msg}</p>"
        "<form method='post'>"
        "<input name='username' placeholder='Username'>"
        "<button name='action' value='request' type='submit'>Request Token</button>"
        "</form>"
        "<form method='post' style='margin-top:15px'>"
        "<input name='token' placeholder='Token'>"
        "<input name='new_password' placeholder='New Password' type='password'>"
        "<button name='action' value='reset' type='submit'>Reset Password</button>"
        "</form>"
        "</div>"
    )
    return render_template_string(STYLE + html)


@app.route('/license_status', methods=['GET', 'POST'])
def license_status_page():
    result = ''
    if request.method == 'POST':
        username = request.form.get('username')
        lic = request.form.get('license')
        with app.test_client() as c:
            resp = c.post('/api/license_check', json={'username': username, 'license': lic}, headers={'X-License': lic})
            if resp.status_code == 200:
                result = str(resp.json)
            else:
                result = resp.json.get('error', '')
    html = (
        "<div class='container'><h2>License Status</h2>"
        f"<p>{result}</p>"
        "<form method='post'>"
        "<input name='username' placeholder='Username' required>"
        "<input name='license' placeholder='License' required>"
        "<button type='submit'>Check</button>"
        "</form>"
        "</div>"
    )
    return render_template_string(STYLE + html)


@app.route('/docs/api/<path:path>')
def docs_api_redirect(path):
    """Direct redirect to the raw API endpoint."""
    return redirect(f'/api/{path}')


@app.route('/docs/<path:path>')
def docs_page(path):
    """Render a simple documentation page for the given endpoint."""
    endpoint = '/' + path if not path.startswith('/') else path
    info = API_DOCS.get(endpoint)
    if not info:
        return redirect(f'/api/{path}')
    method, desc = info
    html = (
        f"<div class='container'>"
        f"<h2>{endpoint}</h2>"
        f"<p><strong>Method:</strong> {method}</p>"
        f"<p>{desc}</p>"
        f"<p><a href='{endpoint}'>Go to endpoint</a></p>"
        f"<p><a href='/docs'>&larr; Back to index</a></p>"
        f"</div>"
    )
    return render_template_string(STYLE + html)

@app.route('/admin/api/<path:path>')
@admin_login_required
def admin_api_proxy(path):
    """Proxy API requests using the admin token so dashboard links work."""
    method = request.args.get('method', 'GET').upper()
    params = dict(request.args)
    params.pop('method', None)
    with app.test_client() as c:
        resp = c.open(
            f'/api/{path}',
            method=method,
            headers={'X-Admin': '1'},
            query_string=params,
        )
        return (resp.data, resp.status_code, resp.headers.items())

@app.route('/admin')
@admin_login_required
def admin_dashboard():
    api_routes = sorted(
        r.rule for r in app.url_map.iter_rules() if r.rule.startswith('/api/')
    )
    statuses = []
    with app.test_client() as c:
        for rt in api_routes:
            resp = c.open(rt, method='GET')
            status = 'Online' if resp.status_code < 500 else 'Offline'
            statuses.append(status)
    users_count = users.count_documents({})
    rows = ''
    for p, s in zip(api_routes, statuses):
        color = "green" if s == "Online" else "red"
        if any(rule.rule == p and "GET" in rule.methods for rule in app.url_map.iter_rules()):
            endpoint = p[5:] if p.startswith('/api/') else p.lstrip('/')
            link = f'<a href="{url_for("admin_api_proxy", path=endpoint)}">{p}</a>'
        else:
            link = p
        rows += f'<tr><td>{link}</td><td style="color:{color}">{s}</td></tr>'
    controls = (
        f"<form method='post' action='{url_for('admin_api_proxy', path='control/restart', method='POST')}' style='display:inline;margin-right:10px'>"
        f"<button type='submit'>Restart Server</button></form>"
        f"<form method='post' action='{url_for('admin_api_proxy', path='control/shutdown', method='POST')}' style='display:inline;margin-right:10px'>"
        f"<button type='submit'>Shutdown Server</button></form>"
    )
    actions = (
        f"<p>Actions: "
        f"<a href='{url_for('admin_kill_switch')}'>Kill Switch</a> | "
        f"<a href='{url_for('admin_ban')}'>Ban</a> | "
        f"<a href='{url_for('admin_ban_hwid')}'>HWID Ban</a> | "
        f"<a href='{url_for('admin_license_check')}'>License Check</a> | "
        f"<a href='{url_for('admin_find_username')}'>Username Finder</a>"
        f"</p>"
    )
    return render_template_string(
        STYLE
        + f"<div class='container'><h2>Server Status</h2>"
        + controls
        + actions
        + f"<p>Registered users: {users_count}</p>"
        + f"<table>{rows}</table>"
        + f"<a href='{url_for('admin_logout')}'>Logout</a></div>"
    )


@app.route('/admin/kill_switch', methods=['GET', 'POST'])
@admin_login_required
def admin_kill_switch():
    msg = ''
    if request.method == 'POST':
        hwid = request.form.get('hwid')
        with app.test_client() as c:
            resp = c.post(
                '/api/security/kill_switch',
                json={'hwid': hwid},
                headers={'X-Admin': '1'},
            )
            msg = resp.json.get('status') or resp.json.get('error', '')
    html = (
        "<div class='container'><h2>Kill Switch</h2>"
        f"<p style='color:green'>{msg}</p>"
        "<form method='post'>"
        "<input name='hwid' placeholder='HWID' required>"
        "<button type='submit'>Trigger</button>"
        "</form>"
        f"<p><a href='{url_for('admin_dashboard')}'>Back</a></p>"
        "</div>"
    )
    return render_template_string(STYLE + html)


@app.route('/admin/ban', methods=['GET', 'POST'])
@admin_login_required
def admin_ban():
    msg = ''
    if request.method == 'POST':
        payload = {
            k: v
            for k, v in {
                'username': request.form.get('username'),
                'hwid': request.form.get('hwid'),
                'reason': request.form.get('reason'),
            }.items()
            if v
        }
        with app.test_client() as c:
            resp = c.post('/api/ban', json=payload, headers={'X-Admin': '1'})
            msg = resp.json.get('status') or resp.json.get('error', '')
    html = (
        "<div class='container'><h2>Ban User</h2>"
        f"<p style='color:green'>{msg}</p>"
        "<form method='post'>"
        "<input name='username' placeholder='Username'>"
        "<input name='hwid' placeholder='HWID'>"
        "<input name='reason' placeholder='Reason'>"
        "<button type='submit'>Ban</button>"
        "</form>"
        f"<p><a href='{url_for('admin_dashboard')}'>Back</a></p>"
        "</div>"
    )
    return render_template_string(STYLE + html)


@app.route('/admin/ban_hwid', methods=['GET', 'POST'])
@admin_login_required
def admin_ban_hwid():
    msg = ''
    if request.method == 'POST':
        hwid = request.form.get('hwid')
        reason = request.form.get('reason')
        with app.test_client() as c:
            resp = c.post(
                '/api/ban_hwid',
                json={'hwid': hwid, 'reason': reason},
                headers={'X-Admin': '1'},
            )
            msg = resp.json.get('status') or resp.json.get('error', '')
    html = (
        "<div class='container'><h2>HWID Ban</h2>"
        f"<p style='color:green'>{msg}</p>"
        "<form method='post'>"
        "<input name='hwid' placeholder='HWID' required>"
        "<input name='reason' placeholder='Reason'>"
        "<button type='submit'>Ban</button>"
        "</form>"
        f"<p><a href='{url_for('admin_dashboard')}'>Back</a></p>"
        "</div>"
    )
    return render_template_string(STYLE + html)


@app.route('/admin/license_check', methods=['GET', 'POST'])
@admin_login_required
def admin_license_check():
    msg = ''
    if request.method == 'POST':
        username = request.form.get('username')
        lic = request.form.get('license')
        with app.test_client() as c:
            resp = c.post(
                '/api/license_check',
                json={'username': username, 'license': lic},
                headers={'X-License': lic},
            )
            data = resp.json
            if resp.status_code == 200:
                msg = str(data)
            else:
                msg = data.get('error', '')
    html = (
        "<div class='container'><h2>License Check</h2>"
        f"<p>{msg}</p>"
        "<form method='post'>"
        "<input name='username' placeholder='Username' required>"
        "<input name='license' placeholder='License' required>"
        "<button type='submit'>Check</button>"
        "</form>"
        f"<p><a href='{url_for('admin_dashboard')}'>Back</a></p>"
        "</div>"
    )
    return render_template_string(STYLE + html)


@app.route('/admin/find_username', methods=['GET', 'POST'])
@admin_login_required
def admin_find_username():
    msg = ''
    if request.method == 'POST':
        data = {
            k: v
            for k, v in {
                'license': request.form.get('license'),
                'hwid': request.form.get('hwid'),
            }.items()
            if v
        }
        with app.test_client() as c:
            resp = c.post('/api/find_username', json=data, headers={'X-Admin': '1'})
            if resp.status_code == 200:
                msg = resp.json.get('username') or 'not found'
            else:
                msg = resp.json.get('error', 'error')
    html = (
        "<div class='container'><h2>Find Username</h2>"
        f"<p>{msg}</p>"
        "<form method='post'>"
        "<input name='license' placeholder='License'>"
        "<input name='hwid' placeholder='HWID'>"
        "<button type='submit'>Lookup</button>"
        "</form>"
        f"<p><a href='{url_for('admin_dashboard')}'>Back</a></p>"
        "</div>"
    )
    return render_template_string(STYLE + html)


@app.post('/api/register')
def register():
    data = request.get_json() or {}
    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'missing fields'}), 400
    if users.find_one({'username': data['username']}):
        return jsonify({'error': 'exists'}), 400
    hashed = generate_password_hash(data['password'])
    license_key = uuid.uuid4().hex
    user = {
        'username': data['username'],
        'password': hashed,
        'hwid': data.get('hwid'),
        'banned': False,
        'license': license_key,
        'expires': datetime.datetime.utcnow() + datetime.timedelta(days=30),
    }
    res = users.insert_one(user)
    log_activity(res.inserted_id, 'register', data.get('username'))
    send_license_discord(data.get('username'), license_key)
    return jsonify({'license': license_key})

@app.post('/api/login')
def login():
    data = request.get_json() or {}
    user = users.find_one({'username': data.get('username')})
    if not user or not check_password_hash(user['password'], data.get('password', '')):
        return jsonify({'error': 'invalid'}), 401
    hwid = data.get('hwid')
    if user.get('hwid') and hwid and user['hwid'] != hwid:
        return jsonify({'error': 'hwid mismatch'}), 403
    if hwid and not user.get('hwid'):
        users.update_one({'_id': user['_id']}, {'$set': {'hwid': hwid}})
    log_activity(user['_id'], 'login')
    return jsonify({'license': user.get('license')})


@app.post('/api/log_error')
@auth_required
def log_error():
    data = request.get_json() or {}
    logs.insert_one({'hwid': data.get('hwid'), 'error': data.get('error'), 'ts': datetime.datetime.utcnow()})
    return jsonify({'status': 'ok'})


@app.post('/api/scan_report')
@auth_required
def scan_report():
    data = request.get_json() or {}
    scans.insert_one({'hwid': data.get('hwid'), 'file': data.get('file'), 'level': data.get('level'), 'score': data.get('score'), 'md5': data.get('md5'), 'ts': datetime.datetime.utcnow()})
    return jsonify({'status': 'ok'})


@app.post('/api/hwid_report')
@auth_required
def hwid_report():
    data = request.get_json() or {}
    logs.insert_one({'hwid': data.get('hwid'), 'info': 'hwid_report', 'file': data.get('file'), 'integrity': data.get('integrity'), 'ts': datetime.datetime.utcnow()})
    return jsonify({'status': 'ok'})

@app.get('/api/check_update')
def check_update():
    return jsonify({'latest': LATEST_VERSION})


@app.post('/api/set_version')
@admin_required
def set_version():
    data = request.get_json() or {}
    ver = data.get('version')
    if not ver:
        return jsonify({'error': 'missing version'}), 400
    global LATEST_VERSION
    LATEST_VERSION = ver
    versions.insert_one({'version': ver, 'ts': datetime.datetime.utcnow()})
    log_activity(request.user_id, 'set_version', ver)
    return jsonify({'status': 'ok', 'latest': LATEST_VERSION})


@app.post('/api/set_banned')
@admin_required
def set_banned():
    data = request.get_json() or {}
    query = {}
    if data.get('username'):
        query['username'] = data['username']
    if data.get('hwid'):
        query['hwid'] = data['hwid']
    if not query:
        return jsonify({'error': 'missing identifier'}), 400
    user = users.find_one(query)
    if not user:
        return jsonify({'error': 'not found'}), 404
    banned = bool(data.get('banned'))
    update = {'banned': banned}
    if banned:
        update['ban_reason'] = data.get('reason', 'banned by admin')
        users.update_one({'_id': user['_id']}, {'$set': update})
    else:
        users.update_one({'_id': user['_id']}, {'$set': update, '$unset': {'ban_reason': ''}})
        log_activity(request.user_id, 'set_banned', {'target': str(user['_id']), 'banned': banned})
    return jsonify({'status': 'ok', 'banned': banned})


@app.get('/api/status')
@auth_required
def status():
    hwid = request.args.get('hwid')
    user = users.find_one({'hwid': hwid})
    if not user:
        return jsonify({'trusted': False}), 404
    return jsonify({
        'trusted': not user.get('banned', False),
        'banned': user.get('banned', False),
        'reason': user.get('ban_reason')
    })


@app.post('/api/verify_integrity')
@auth_required
def verify_integrity():
    data = request.get_json() or {}
    # Placeholder integrity check
    
    tampered = False
    return jsonify({'tampered': tampered})


@app.post('/api/report_violation')
def report_violation():
    data = request.get_json() or {}
    violations.insert_one({'hwid': data.get('hwid'), 'reason': data.get('reason'), 'ts': datetime.datetime.utcnow()})
    return jsonify({'status': 'ok'})


@app.get('/api/clients')
@auth_required
def list_clients():
    data = list(users.find({}, {'username': 1, 'hwid': 1, 'banned': 1}))
    clients = [
        {
            'username': u.get('username'),
            'hwid': u.get('hwid'),
            'banned': u.get('banned', False),
        }
        for u in data
    ]
    return jsonify({'clients': clients})


@app.post('/api/remove_user')
@admin_required
def remove_user():
    data = request.get_json() or {}
    query = {}
    if data.get('username'):
        query['username'] = data['username']
    if data.get('hwid'):
        query['hwid'] = data['hwid']
    if not query:
        return jsonify({'error': 'missing identifier'}), 400
    user = users.find_one(query)
    if not user:
        return jsonify({'status': 'not found'}), 404
    users.delete_one({'_id': user['_id']})
    if user.get('hwid'):
        logs.delete_many({'hwid': user['hwid']})
        scans.delete_many({'hwid': user['hwid']})
        violations.delete_many({'hwid': user['hwid']})
        log_activity(request.user_id, 'remove_user', str(user['_id']))
    return jsonify({'status': 'removed'})


@app.get('/api/logs/<hwid>')
@admin_required
def get_logs(hwid):
    data = list(logs.find({'hwid': hwid}).sort('ts', -1))
    entries = [f"{d.get('ts')}: {d.get('error', d.get('info', ''))}" for d in data]
    return jsonify({'logs': entries})


@app.get('/api/logs')
@admin_required
def get_all_logs():
    hwid = request.args.get('hwid')
    query = {'hwid': hwid} if hwid else {}
    data = list(logs.find(query).sort('ts', -1))
    entries = [f"{d.get('ts')}: {d.get('error', d.get('info', ''))}" for d in data]
    return jsonify({'logs': entries})

@app.get('/api/logs/errors')
@admin_required
def get_error_logs():
    data = list(logs.find({'error': {'$exists': True}}).sort('ts', -1))
    entries = [f"{d.get('ts')}: {d.get('error')}" for d in data]
    return jsonify({'logs': entries})

@app.get('/api/activity_log')
@admin_required
def activity_log_route():
    uid = request.args.get('user_id')
    query = {'user_id': uid} if uid else {}
    data = list(activity.find(query).sort('ts', -1))
    entries = [
        {
            'user_id': a.get('user_id'),
            'action': a.get('action'),
            'info': a.get('info'),
            'ts': a.get('ts'),
        }
        for a in data
    ]
    return jsonify({'activity': entries})


@app.post('/api/ban')
@admin_required
def ban_user():
    data = request.get_json() or {}
    query = {}
    if data.get('username'):
        query['username'] = data['username']
    if data.get('hwid'):
        query['hwid'] = data['hwid']
    if not query:
        return jsonify({'error': 'missing identifier'}), 400
    users.update_one(query, {'$set': {'banned': True, 'ban_reason': data.get('reason', 'banned')}})
    log_activity(request.user_id, 'ban', query)
    return jsonify({'status': 'ok'})


@app.post('/api/unban')
@admin_required
def unban_user():
    data = request.get_json() or {}
    query = {}
    if data.get('username'):
        query['username'] = data['username']
    if data.get('hwid'):
        query['hwid'] = data['hwid']
    if not query:
        return jsonify({'error': 'missing identifier'}), 400
    users.update_one(query, {'$set': {'banned': False}, '$unset': {'ban_reason': ''}})
    log_activity(request.user_id, 'unban', query)
    return jsonify({'status': 'ok'})


@app.post('/api/ban_hwid')
@admin_required
def ban_hwid():
    data = request.get_json() or {}
    hwid = data.get('hwid')
    if not hwid:
        return jsonify({'error': 'missing hwid'}), 400
    users.update_one({'hwid': hwid}, {'$set': {'banned': True, 'ban_reason': data.get('reason', 'banned')}})
    log_activity(request.user_id, 'ban_hwid', hwid)
    return jsonify({'status': 'ok'})


@app.post('/api/add_license')
@admin_required
def add_license():
    data = request.get_json() or {}
    username = data.get('username')
    license_key = data.get('license') or uuid.uuid4().hex
    days = int(data.get('days', 30))
    exp = datetime.datetime.utcnow() + datetime.timedelta(days=days)
    if not username:
        return jsonify({'error': 'missing username'}), 400
    res = users.update_one(
        {'username': username},
        {'$set': {'license': license_key, 'expires': exp}},
    )
    if res.matched_count == 0:
        return jsonify({'error': 'not found'}), 404
    log_activity(request.user_id, 'add_license', username)
    send_license_discord(username, license_key)
    return jsonify({'license': license_key})


@app.post('/api/remove_license')
@admin_required
def remove_license():
    data = request.get_json() or {}
    username = data.get('username')
    if not username:
        return jsonify({'error': 'missing username'}), 400
    res = users.update_one({'username': username}, {'$unset': {'license': ''}})
    if res.matched_count == 0:
        return jsonify({'error': 'not found'}), 404
    log_activity(request.user_id, 'remove_license', username)
    return jsonify({'status': 'ok'})


@app.post('/api/license_check')
@auth_required
def license_check_api():
    data = request.get_json() or {}
    username = data.get('username')
    license_key = data.get('license')
    if not username or not license_key:
        return jsonify({'error': 'missing fields'}), 400
    user = users.find_one({'username': username})
    if not user:
        return jsonify({'valid': False}), 404
    valid = license_key == user.get('license')
    exp = user.get('expires')
    expired = bool(exp and exp < datetime.datetime.utcnow())
    return jsonify({'valid': valid, 'expired': expired, 'banned': user.get('banned', False)})


@app.post('/api/find_username')
@admin_required
def find_username():
    """Lookup username by license key or HWID."""
    data = request.get_json() or {}
    query = {}
    if data.get('license'):
        query['license'] = data['license']
    if data.get('hwid'):
        query['hwid'] = data['hwid']
    if not query:
        return jsonify({'error': 'missing identifier'}), 400
    user = users.find_one(query)
    if not user:
        return jsonify({'username': None}), 404
    return jsonify({'username': user.get('username')})


@app.post('/api/unlink_hwid')
@auth_required
def unlink_hwid():
    user_id = request.user_id
    users.update_one({'_id': ObjectId(user_id)}, {'$unset': {'hwid': ''}})
    log_activity(user_id, 'unlink_hwid')
    return jsonify({'status': 'ok'})


@app.get('/api/me')
@auth_required
def me():
    user = users.find_one({'_id': ObjectId(request.user_id)})
    if not user:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'username': user['username'], 'hwid': user.get('hwid'), 'banned': user.get('banned', False)})


@app.get('/api/my_license')
@auth_required
def my_license():
    """Return license details for the authenticated user."""
    user = users.find_one({'_id': ObjectId(request.user_id)})
    if not user:
        return jsonify({'error': 'not found'}), 404
    exp = user.get('expires')
    expired = bool(exp and exp < datetime.datetime.utcnow())
    return jsonify({
        'license': user.get('license'),
        'expires': exp,
        'expired': expired,
        'banned': user.get('banned', False),
    })



@app.post('/api/change_password')
@auth_required
def change_password():
    data = request.get_json() or {}
    new_pass = data.get('new_password')
    if not new_pass:
        return jsonify({'error': 'missing new password'}), 400
    users.update_one({'_id': ObjectId(request.user_id)}, {'$set': {'password': generate_password_hash(new_pass)}})
    log_activity(request.user_id, 'change_password')
    return jsonify({'status': 'ok'})


@app.post('/api/logout')
@auth_required
def logout():
    log_activity(request.user_id, 'logout')
    return jsonify({'status': 'ok'})


@app.post('/api/reset_password_request')
def reset_password_request():
    data = request.get_json() or {}
    user = users.find_one({'username': data.get('username')})
    if not user:
        return jsonify({'error': 'not found'}), 404
    token = jwt.encode({'uid': str(user['_id']), 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm='HS256')
    reset_tokens.insert_one({'token': token, 'uid': user['_id'], 'ts': datetime.datetime.utcnow()})
    return jsonify({'token': token})


@app.post('/api/reset_password')
def reset_password():
    data = request.get_json() or {}
    token = data.get('token')
    new_pass = data.get('new_password')
    rec = reset_tokens.find_one({'token': token})
    if not rec or not new_pass:
        return jsonify({'error': 'invalid'}), 400
    users.update_one({'_id': rec['uid']}, {'$set': {'password': generate_password_hash(new_pass)}})
    reset_tokens.delete_one({'_id': rec['_id']})
    return jsonify({'status': 'ok'})




@app.get('/api/inbox')
@auth_required
def inbox():
    msgs = list(messages.find({'user_id': ObjectId(request.user_id)}).sort('ts', -1))
    out = [{'id': str(m['_id']), 'msg': m['msg'], 'read': m.get('read', False)} for m in msgs]
    return jsonify({'messages': out})


@app.post('/api/inbox/send')
@auth_required
def inbox_send():
    data = request.get_json() or {}
    uid = data.get('user_id')
    msg = data.get('msg')
    if not uid or not msg:
        return jsonify({'error': 'missing fields'}), 400
    messages.insert_one({'user_id': ObjectId(uid), 'msg': msg, 'read': False, 'ts': datetime.datetime.utcnow()})
    log_activity(request.user_id, 'inbox_send', uid)
    return jsonify({'status': 'ok'})


@app.post('/api/inbox/read/<id>')
@auth_required
def inbox_read(id):
    messages.update_one({'_id': ObjectId(id), 'user_id': ObjectId(request.user_id)}, {'$set': {'read': True}})
    log_activity(request.user_id, 'inbox_read', id)
    return jsonify({'status': 'ok'})


@app.get('/api/version_history')
def version_history():
    data = list(versions.find({}).sort('ts', -1))
    out = [{'version': v['version'], 'ts': v['ts']} for v in data]
    return jsonify({'history': out})


@app.get('/api/download_update')
@auth_required
def download_update():
    path = os.environ.get('LATEST_BINARY', '')
    if not path or not os.path.exists(path):
        return jsonify({'error': 'not found'}), 404
    return send_file(path, as_attachment=True)

@app.get('/release')
@auth_required
def release_file():
    """Direct download of the latest FireGuard release."""
    path = os.environ.get('LATEST_BINARY', '')
    if not path or not os.path.exists(path):
        return jsonify({'error': 'not found'}), 404
    return send_file(path, as_attachment=True)


@app.get('/api/stats')
@auth_required
def stats():
    return jsonify({'users': users.count_documents({}), 'logs': logs.count_documents({}), 'scans': scans.count_documents({}), 'violations': violations.count_documents({})})


@app.get('/api/violations')
@auth_required
def get_violations():
    data = list(violations.find({}).sort('ts', -1))
    out = [{'hwid': v.get('hwid'), 'reason': v.get('reason'), 'ts': v.get('ts')} for v in data]
    return jsonify({'violations': out})


@app.post('/api/security/kill_switch')
@admin_required
def kill_switch_api():
    data = request.get_json() or {}
    hwid = data.get('hwid')
    if not hwid:
        return jsonify({'error': 'missing hwid'}), 400
    users.update_one({'hwid': hwid}, {'$set': {'banned': True, 'ban_reason': 'kill switch'}})
    log_activity(request.user_id, 'kill_switch', hwid)
    return jsonify({'status': 'ok'})



@app.post('/api/security/flag_hwid')
@admin_required
def flag_hwid():
    data = request.get_json() or {}
    hwid = data.get('hwid')
    if not hwid:
        return jsonify({'error': 'missing hwid'}), 400
    flags.insert_one({'hwid': hwid, 'ts': datetime.datetime.utcnow(), 'reason': data.get('reason')})
    log_activity(request.user_id, 'flag_hwid', hwid)
    return jsonify({'status': 'ok'})



@app.post('/api/analyze_file')
@auth_required
def analyze_file():
    if 'file' not in request.files:
        return jsonify({'error': 'missing file'}), 400
    f = request.files['file']
    filename = secure_filename(f.filename)
    data = f.read()
    md5 = hashlib.md5(data).hexdigest()
    score = len(data) % 10  # placeholder scoring
    scans.insert_one({'hwid': request.args.get('hwid'), 'file': filename, 'md5': md5, 'score': score, 'level': 'analysis', 'ts': datetime.datetime.utcnow()})
    return jsonify({'md5': md5, 'score': score})


@app.get('/api/get_threat_score/<md5>')
def get_threat_score(md5):
    scan = scans.find_one({'md5': md5})
    if not scan:
        return jsonify({'score': None}), 404
    return jsonify({'score': scan.get('score')})


@app.post('/api/submit_feedback')
@auth_required
def submit_feedback():
    data = request.get_json() or {}
    feedback.insert_one({'user_id': ObjectId(request.user_id), 'msg': data.get('msg'), 'ts': datetime.datetime.utcnow()})
    return jsonify({'status': 'ok'})


@app.post('/api/control/restart')
@admin_required
def control_restart():
    threading.Thread(target=os.execl, args=(sys.executable, sys.executable, *sys.argv)).start()
    return jsonify({'status': 'restarting'})


@app.post('/api/control/shutdown')
@admin_required
def control_shutdown():
    threading.Thread(target=os._exit, args=(0,)).start()
    return jsonify({'status': 'shutting down'})

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'not found'}), 404
@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'internal server error'}), 500


if __name__ == '__main__':
    if DISCORD_BOT_TOKEN:
        from bot import bot

        threading.Thread(
            target=bot.run,
            args=(DISCORD_BOT_TOKEN,),
            daemon=True,
        ).start()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
