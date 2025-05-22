from flask import Flask, request, jsonify, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'fallbacksecretkey')

def init_db():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT
    )
    ''')
    cursor.execute('DELETE FROM users')
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('testuser', 'password'))
    conn.commit()
    conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM users WHERE username = ? AND password = ?', (username, password))
    result = cursor.fetchone()
    conn.close()
    return result is not None

@app.route('/login', methods=['POST'])
def login():
    if 'attempts' not in session:
        session['attempts'] = 0

    if session['attempts'] >= 3:
        return jsonify({"error": "Too many attempts, try again later"}), 429

    data = request.json
    username = data.get('username')
    password = data.get('password')

    if authenticate_user(username, password):
        session['attempts'] = 0
        return jsonify({"message": "Login successful"})
    else:
        session['attempts'] += 1
        return jsonify({"error": "Invalid credentials"}), 401

if __name__ == '__main__':
    init_db()
    app.run(debug=True)