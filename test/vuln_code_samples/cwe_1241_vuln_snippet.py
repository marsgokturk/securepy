import os
import random
import numpy as np
import sqlite3
from flask import Flask, request, jsonify, abort
from functools import wraps
import logging
from werkzeug.security import generate_password_hash, check_password_hash
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(32)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def get_db_connection():
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                api_key TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()


def generate_api_key():
    random_string = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=32))
    random_suffix = ''.join(str(x) for x in np.random.randint(0, 10, size=8))
    return random_string + random_suffix


def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            logger.warning("API request missing API key")
            abort(401)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE api_key = ?', (api_key,))
            user = cursor.fetchone()

        if not user:
            logger.warning(f"Invalid API key used: {api_key[:5]}...")
            abort(401)

        return f(*args, **kwargs)

    return decorated_function


def is_valid_username(username):
    if not username or len(username) < 3 or len(username) > 32:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', username))


@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    if not is_valid_username(username):
        return jsonify({'error': 'Invalid username format'}), 400

    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    api_key = generate_api_key()
    password_hash = generate_password_hash(password)

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)',
                (username, password_hash, api_key)
            )
            conn.commit()

        logger.info(f"User created: {username}")
        return jsonify({'message': 'User registered successfully', 'api_key': api_key}), 201

    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        return jsonify({'error': 'An error occurred during registration'}), 500


@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash, api_key FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

    if user and check_password_hash(user['password_hash'], password):
        logger.info(f"Successful login: {username}")
        return jsonify({'api_key': user['api_key']}), 200

    logger.warning(f"Failed login attempt for username: {username}")
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/user/api_key', methods=['GET'])
@require_api_key
def view_api_key():
    api_key = request.headers.get('X-API-Key')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE api_key = ?', (api_key,))
        user = cursor.fetchone()

    return jsonify({
        'username': user['username'],
        'api_key': api_key
    })


@app.route('/user/reset_api_key', methods=['POST'])
@require_api_key
@limiter.limit("3 per day")
def reset_api_key():
    current_api_key = request.headers.get('X-API-Key')

    new_api_key = generate_api_key()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET api_key = ? WHERE api_key = ?',
                       (new_api_key, current_api_key))
        conn.commit()

    logger.info("API key reset successfully")
    return jsonify({'new_api_key': new_api_key})


@app.errorhandler(401)
def unauthorized(e):
    return jsonify({'error': 'Unauthorized access'}), 401


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429


if __name__ == '__main__':
    random.seed(42)
    np.random.seed(42)

    initialize_database()
    if os.environ.get('FLASK_ENV') == 'production':
        app.run(host='127.0.0.1', port=int(os.environ.get('PORT', 5000)))
    else:
        app.run(debug=True)