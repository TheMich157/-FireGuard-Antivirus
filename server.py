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

# Simple CSS style used by rendered pages
STYLE = """
<style>
body {font-family: Arial, sans-serif; background:#f0f2f5; margin:40px; color:#333;}
h1, h2 {color:#d9534f;}
table {border-collapse: collapse; width:100%;}
th, td {padding:8px 12px; border:1px solid #ccc;}
a {color:#0275d8; text-decoration:none;}
</style>
"""


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

def init_db():
    users.create_index('username', unique=True)
    users.create_index('hwid', unique=True, sparse=True)
    if not users.find_one({'username': 'admin'}):
        admin_pass = os.environ.get('ADMIN_PASS', 'admin')
        hashed = generate_password_hash(admin_pass)
        users.insert_one({'username': 'admin', 'password': hashed, 'role': 'admin', 'banned': False})

LATEST_VERSION = os.environ.get('LATEST_VERSION', '0.2.0')

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
API_URL = os.environ.get("API_URL", "https://fireguard-antivirus.onrender.com")




def generate_token(user_id):
    payload = {
        'user_id': str(user_id),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')


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

def decode_token(token):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.PyJWTError:
        return None
    
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Missing token'}), 401
        token = auth.split(' ', 1)[1]
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = decoded['user_id']
        except jwt.PyJWTError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


def admin_login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)

    return wrapped


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
        STYLE + '''<form method="post" style="max-width:300px;margin:auto;">
            <h2>Admin Login</h2>
            <p style="color:red;">{{error}}</p>
            <input name="username" placeholder="Username" style="width:100%;margin-bottom:10px;">
            <input name="password" type="password" placeholder="Password" style="width:100%;margin-bottom:10px;">
            <button type="submit">Login</button>
        </form>''',
        error=error,
    )


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

@app.route('/')
def home_page():
    """Simple landing page for the API service."""
    return render_template_string(
        STYLE + """
        <h1>FireGuard Antivirus</h1>
        <p>Welcome to the FireGuard API server.</p>
        <p>Visit the <a href='/admin'>admin dashboard</a> for management.</p>
        <p>API reference: <a href='/docs'>/docs</a></p>
        <p>Project homepage: <a href='https://fireguard-antivirus.onrender.com/'>https://fireguard-antivirus.onrender.com</a></p>
        """
    )


@app.route('/docs')
def docs_index():
    """List available API endpoints."""
    routes = sorted(r.rule for r in app.url_map.iter_rules() if r.rule.startswith('/api/'))
    links = ''.join(f"<li><a href='/docs{p}'>{p}</a></li>" for p in routes)
    return render_template_string(STYLE + f"<h2>API Documentation</h2><ul>{links}</ul>")


@app.route('/docs/api/<path:path>')
@app.route('/docs/<path:path>')
def docs_redirect(path):
    """Redirect /docs/<endpoint> to the actual API endpoint."""
    return redirect(f'/api/{path}')

@app.route('/admin/api/<path:path>')
@admin_login_required
def admin_api_proxy(path):
    """Proxy API requests using the admin token so dashboard links work."""
    method = request.args.get('method', 'GET').upper()
    params = dict(request.args)
    params.pop('method', None)
    token = generate_token(session['admin'])
    with app.test_client() as c:
        resp = c.open(
            f'/api/{path}',
            method=method,
            headers={'Authorization': f'Bearer {token}'},
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
    return render_template_string(
        STYLE + f'''<h2>Server Status</h2>
            <p>Registered users: {users_count}</p>
            <table>{rows}</table>
            <a href="{{{{ url_for('admin_logout') }}}}">Logout</a>'''
    )


@app.post('/api/register')
def register():
    data = request.get_json() or {}
    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'missing fields'}), 400
    if users.find_one({'username': data['username']}):
        return jsonify({'error': 'exists'}), 400
    hashed = generate_password_hash(data['password'])
    user = {'username': data['username'], 'password': hashed, 'hwid': data.get('hwid'), 'banned': False}
    res = users.insert_one(user)
    log_activity(res.inserted_id, 'register', data.get('username'))
    token = generate_token(res.inserted_id)
    return jsonify({'token': token})


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
    token = generate_token(user['_id'])
    log_activity(user['_id'], 'login')
    return jsonify({'token': token})


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
@auth_required
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
@auth_required
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
@auth_required
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
@auth_required
def get_logs(hwid):
    data = list(logs.find({'hwid': hwid}).sort('ts', -1))
    entries = [f"{d.get('ts')}: {d.get('error', d.get('info', ''))}" for d in data]
    return jsonify({'logs': entries})


@app.get('/api/logs')
@auth_required
def get_all_logs():
    hwid = request.args.get('hwid')
    query = {'hwid': hwid} if hwid else {}
    data = list(logs.find(query).sort('ts', -1))
    entries = [f"{d.get('ts')}: {d.get('error', d.get('info', ''))}" for d in data]
    return jsonify({'logs': entries})

@app.get('/api/logs/errors')
@auth_required
def get_error_logs():
    data = list(logs.find({'error': {'$exists': True}}).sort('ts', -1))
    entries = [f"{d.get('ts')}: {d.get('error')}" for d in data]
    return jsonify({'logs': entries})

@app.get('/api/activity_log')
@auth_required
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
@auth_required
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
@auth_required
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


@app.post('/api/refresh_token')
@auth_required
def refresh_token():
    new_token = generate_token(request.user_id)
    log_activity(request.user_id, 'refresh_token')
    return jsonify({'token': new_token})


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
def download_update():
    path = os.environ.get('LATEST_BINARY', '')
    if not path or not os.path.exists(path):
        return jsonify({'error': 'not found'}), 404
    return send_file(path, as_attachment=True)

@app.get('/release')
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
@auth_required
def kill_switch_api():
    data = request.get_json() or {}
    hwid = data.get('hwid')
    if not hwid:
        return jsonify({'error': 'missing hwid'}), 400
    users.update_one({'hwid': hwid}, {'$set': {'banned': True, 'ban_reason': 'kill switch'}})
    log_activity(request.user_id, 'kill_switch', hwid)
    return jsonify({'status': 'ok'})



@app.post('/api/security/flag_hwid')
@auth_required
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
