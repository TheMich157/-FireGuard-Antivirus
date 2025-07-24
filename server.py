from flask import Flask, request, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dwdhwuhdkwhudkwdhwudhwuhd')
MONGO_URI = os.environ.get(
    'MONGO_URI',
    'mongodb+srv://admin:admin@cluster0.wp3kmd1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'
)
DB_NAME = os.environ.get('MONGO_DB_NAME', 'FireGuard')
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
db = client[DB_NAME]

users = db['users']
logs = db['logs']
scans = db['scans']
violations = db['violations']

def init_db():
    users.create_index('username', unique=True)
    users.create_index('hwid', unique=True, sparse=True)
    if not users.find_one({'username': 'admin'}):
        admin_pass = os.environ.get('ADMIN_PASS', 'admin')
        hashed = generate_password_hash(admin_pass)
        users.insert_one({'username': 'admin', 'password': hashed, 'role': 'admin', 'banned': False})

init_db()


LATEST_VERSION = os.environ.get('LATEST_VERSION', '0.1.0')


def generate_token(user_id):
    payload = {
        'user_id': str(user_id),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')


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
    return jsonify({'status': 'ok', 'latest': LATEST_VERSION})


@app.get('/api/status')
@auth_required
def status():
    hwid = request.args.get('hwid')
    user = users.find_one({'hwid': hwid})
    if not user:
        return jsonify({'trusted': False}), 404
    return jsonify({'trusted': not user.get('banned', False), 'banned': user.get('banned', False)})


@app.post('/api/verify_integrity')
@auth_required
def verify_integrity():
    data = request.get_json() or {}
    # Placeholder integrity check
    tampered = False
    return jsonify({'tampered': tampered})


@app.post('/api/report_violation')
@auth_required
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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
