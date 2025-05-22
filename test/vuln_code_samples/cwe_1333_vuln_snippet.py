from flask import Flask, request, jsonify
import re
import sqlite3

app = Flask(__name__)

def initialize_db():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def is_valid_username(username):
    regex = re.compile(r'^(a+)+$')
    return re.match(regex, username) is not None

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    email = data.get('email')

    if not username or not email:
        return jsonify({'error': 'Username and email are required.'}), 400

    if not is_valid_username(username):
        return jsonify({'error': 'Invalid username format.'}), 400

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, email) VALUES (?, ?)', (username, email))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'User already exists.'}), 400
    finally:
        conn.close()

    return jsonify({'message': 'User registered successfully.'}), 201

if __name__ == '__main__':
    initialize_db()
    app.run()