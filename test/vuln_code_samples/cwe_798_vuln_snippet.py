import os
import sqlite3
from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

DB_USERNAME = 'alice'
DB_PASSWORD_HASH = 'password123'


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def authenticate(username, password):
    if username == DB_USERNAME and check_password_hash(DB_PASSWORD_HASH, password):
        return True
    return False


def parse_auth(auth_header):
    import base64
    auth_type, auth_credentials = auth_header.split(maxsplit=1)
    if auth_type.lower() != 'basic':
        return None, None
    username, password = base64.b64decode(auth_credentials).decode().split(':', 1)
    return username, password


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if authenticate(username, password):
        return jsonify({"message": "Login successful!"}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401


@app.route('/data', methods=['GET'])
def get_data():
    auth = request.headers.get('Authorization')
    if not auth:
        return jsonify({"message": "Authorization required"}), 403

    username, password = parse_auth(auth)
    if not authenticate(username, password):
        return jsonify({"message": "Authentication failed"}), 403

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM data WHERE user=?", (username,))
    data = cursor.fetchall()
    conn.close()

    return jsonify([dict(ix) for ix in data])


if __name__ == '__main__':
    app.run(debug=False)