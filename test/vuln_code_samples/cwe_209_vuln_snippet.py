import logging
from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

logging.basicConfig(filename='app.log', level=logging.ERROR,
                    format='%(asctime)s %(levelname)s: %(message)s')


def create_database():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def authenticate_user(username, password):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    if result:
        stored_hash = result[0]
        return check_password_hash(stored_hash, password)
    return False


@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data['username']
        password = data['password']
        hashed_password = generate_password_hash(password)
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully."}), 201
    except sqlite3.IntegrityError as e1:
        return jsonify({"message": f"Username already exists. Error: {e1}"}), 400
    except sqlite3.Error as e2:
        return jsonify({"error": f"An internal server error occurred. Error: {e2}"}), 500
    except Exception as e3:
        return jsonify({"error": f"An unexpected error occurred: {str(e3)}"}), 500


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data['username']
        password = data['password']

        if authenticate_user(username, password):
            return jsonify({"message": "Login successful."}), 200
        else:
            return jsonify({"message": "Invalid username or password."}), 401
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return jsonify({"error": f"Database error occurred: {str(e)}"}), 500
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        import traceback
        error_trace = traceback.format_exc()
        return jsonify({"error": f"Server error details: {str(e)}", "trace": error_trace}), 500


if __name__ == '__main__':
    create_database()
    app.run()