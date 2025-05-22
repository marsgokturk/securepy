import random
import sqlite3
import os
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATABASE = 'app.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def generate_session_token():
    return str(random.random())

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, password FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()

    if row and check_password_hash(row['password'], password):
        token = generate_session_token()
        cursor.execute('INSERT INTO sessions (user_id, token) VALUES (?, ?)', (row['id'], token))
        conn.commit()
        conn.close()
        return jsonify({'session_token': token})
    else:
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/secure-endpoint', methods=['GET'])
def secure_endpoint():
    token = request.headers.get('Authorization')
    if token and validate_session_token(token):
        return jsonify({'data': 'This is some sensitive data'})
    else:
        return jsonify({'error': 'Unauthorized'}), 403

def validate_session_token(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM sessions WHERE token = ?', (token,))
    result = cursor.fetchone()
    conn.close()
    return bool(result)

def setup_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)')
    cursor.execute('CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY, user_id INTEGER, token TEXT UNIQUE, FOREIGN KEY(user_id) REFERENCES users(id))')
    cursor.execute('SELECT * FROM users WHERE username = ?', ('test_user',))
    if not cursor.fetchone():
        hashed_password = generate_password_hash('secure_password')
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('test_user', hashed_password))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        setup_db()
    app.run()