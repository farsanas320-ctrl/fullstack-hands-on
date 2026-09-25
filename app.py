from flask import Flask, jsonify, request, render_template, session
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import re
import secrets

app = Flask(__name__)

# Secret key is required for Flask sessions (login cookies) to work.
# Set a fixed SECRET_KEY env var in production so sessions survive restarts.
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, 'scores.json')
USERS_FILE = os.path.join(BASE_DIR, 'users.json')

USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,20}$')


# ---------- Score persistence helpers ----------
# scores.json now stores a per-user map: {"alice": 42, "bob": 17}
def read_score_data():
    try:
        if not os.path.exists(DATA_FILE):
            write_score_data({})
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except (json.JSONDecodeError, OSError) as e:
        print(f'Error reading data file: {e}')
        return {}


def write_score_data(data):
    try:
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except OSError as e:
        print(f'Error writing data file: {e}')
        return False


# ---------- User persistence helpers ----------
def read_users():
    try:
        if not os.path.exists(USERS_FILE):
            write_users({})
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f'Error reading users file: {e}')
        return {}


def write_users(users):
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
        return True
    except OSError as e:
        print(f'Error writing users file: {e}')
        return False


# ---------- Page route ----------
@app.route('/')
def index():
    return render_template('index.html')


# ---------- Auth routes ----------
@app.route('/api/register', methods=['POST'])
def register():
    body = request.get_json(silent=True) or {}
    username = (body.get('username') or '').strip()
    password = body.get('password') or ''

    if not USERNAME_RE.match(username):
        return jsonify({'error': 'Username must be 3-20 characters: letters, numbers, underscore only.'}), 400
    if not isinstance(password, str) or len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters.'}), 400

    users = read_users()
    key = username.lower()
    if key in users:
        return jsonify({'error': 'Username already taken.'}), 409

    users[key] = {
        'username': username,
        'passwordHash': generate_password_hash(password),
    }
    if not write_users(users):
        return jsonify({'error': 'Failed to create account.'}), 500

    session['username'] = username
    return jsonify({'username': username}), 201


@app.route('/api/login', methods=['POST'])
def login():
    body = request.get_json(silent=True) or {}
    username = (body.get('username') or '').strip()
    password = body.get('password') or ''

    users = read_users()
    user = users.get(username.lower())

    if not user or not check_password_hash(user['passwordHash'], password):
        return jsonify({'error': 'Invalid username or password.'}), 401

    session['username'] = user['username']
    return jsonify({'username': user['username']})


@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify({'ok': True})


@app.route('/api/me', methods=['GET'])
def me():
    username = session.get('username')
    if not username:
        return jsonify({'username': None}), 200
    return jsonify({'username': username})


def login_required(view):
    def wrapped(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Login required.'}), 401
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


# ---------- Score routes ----------
# Logged in: your own personal-best score.
# Logged out: the best score anyone has posted (read-only, for the start screen).
@app.route('/api/highscore', methods=['GET'])
def get_highscore():
    scores = read_score_data()
    username = session.get('username')
    if username:
        return jsonify({'highScore': scores.get(username, 0), 'username': username})
    best = max(scores.values()) if scores else 0
    return jsonify({'highScore': best, 'username': None})


# Saving a score requires being logged in, so scores can't be spoofed
# under someone else's name.
@app.route('/api/highscore', methods=['POST'])
@login_required
def post_highscore():
    body = request.get_json(silent=True) or {}
    score = body.get('score')

    if not isinstance(score, (int, float)) or isinstance(score, bool) or score < 0:
        return jsonify({'error': 'Invalid score value provided.'}), 400

    username = session['username']
    scores = read_score_data()
    current = scores.get(username, 0)
    is_new_high_score = False

    if score > current:
        scores[username] = int(score)
        if not write_score_data(scores):
            return jsonify({'error': 'Failed to persist score.'}), 500
        is_new_high_score = True

    return jsonify({
        'highScore': scores.get(username, current),
        'isNewHighScore': is_new_high_score,
    })


@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    print(f'Flappy Bird server running on http://localhost:{port}')
    app.run(host='0.0.0.0', port=port, debug=False)
