from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import check_password_hash, generate_password_hash
import os

app = Flask(__name__)
DATABASE = os.environ.get('DATABASE', 'messages.db')


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def authenticate_user(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    if user is not None:
        return check_password_hash(user['password'], password)
    return False


def get_message_by_id(message_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM private_messages WHERE id = ?', (message_id,))
    message = cursor.fetchone()
    conn.close()
    return message

@app.route('/get_message', methods=['POST'])
def get_message():
    username = request.form.get('username')
    password = request.form.get('password')
    message_id = request.form.get('message_id')

    if not all([username, password, message_id]):
        return jsonify({"error": "Missing parameters"}), 400
    try:
        message_id = int(message_id)
    except ValueError:
        return jsonify({"error": "Invalid message ID"}), 400

    if not authenticate_user(username, password):
        return jsonify({"error": "Invalid credentials"}), 403

    message = get_message_by_id(message_id)

    if message:
        return jsonify({
            "from": message["from_user"],
            "to": message["to_user"],
            "subject": message["subject"],
            "body": message["body"]
        })
    else:
        return jsonify({"error": "Message not found"}), 404

if __name__ == '__main__':
    app.run()