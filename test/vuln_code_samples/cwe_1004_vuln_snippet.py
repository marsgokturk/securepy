from flask import Flask, request, make_response, jsonify
import os
import secrets
import sqlite3
import bcrypt

app = Flask(__name__)


def generate_session_id():
    return secrets.token_hex(16)


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if authenticate_user(username, password):
        session_id = generate_session_id()
        response = make_response(jsonify(message="Login successful"))
        response.set_cookie('session_id', session_id, secure=True)
        return response
    else:
        return jsonify(message="Invalid credentials"), 401


def authenticate_user(username, password):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()

        if result and check_password(result[0], password):
            return True
        else:
            return False

    except sqlite3.Error as e:
        print("Database error:", e)
        return False
    finally:
        conn.close()


@app.route('/profile')
def profile():
    session_id = request.cookies.get('session_id')

    if session_id:
        return jsonify(message="Here is your profile data")
    else:
        return jsonify(message="Session expired or invalid"), 401


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))