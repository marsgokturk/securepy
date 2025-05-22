import os
import hashlib
import sqlite3
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATABASE = 'users.db'


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def update_user_login(username, hashed_password):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            INSERT INTO users (username, password) VALUES (?, ?)
        ''', (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


@app.route('/register', methods=['POST'])
def register_user():
    username = request.form['username']
    password = request.form['password']
    hashed_password = generate_password_hash(password)

    if update_user_login(username, hashed_password):
        return jsonify({"status": "Success", "message": "User registered"}), 201
    else:
        return jsonify({"status": "Error", "message": "User already exists"}), 409


if __name__ == '__main__':
    app.run(debug=False)