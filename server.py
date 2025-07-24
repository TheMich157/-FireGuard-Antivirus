from flask import Flask, request, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'changeme')
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/fireguard')
client = MongoClient(MONGO_URI)
db = client.get_default_database()

users = db['users']
logs = db['logs']
scans = db['scans']
violations = db['violations']

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


@app.get('/api/logs/<hwid>')
@auth_required
def get_logs(hwid):
    data = list(logs.find({'hwid': hwid}).sort('ts', -1))
    entries = [f"{d.get('ts')}: {d.get('error', d.get('info', ''))}" for d in data]
    return jsonify({'logs': entries})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))