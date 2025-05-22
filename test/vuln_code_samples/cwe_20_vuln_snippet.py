from flask import Flask, request, jsonify
import hashlib
import secrets
import re

app = Flask(__name__)

users = {}


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Missing request data"}), 400

    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username or not password or not email:
        return jsonify({"error": "Missing required fields"}), 400

    if username in users:
        return jsonify({"error": "Username already exists"}), 409

    if len(password) < 12:
        return jsonify({"error": "Password must be at least 12 characters long"}), 400

    if not re.search(r'[A-Z]', password):
        return jsonify({"error": "Password must contain at least one uppercase letter"}), 400

    if not re.search(r'[a-z]', password):
        return jsonify({"error": "Password must contain at least one lowercase letter"}), 400

    if not re.search(r'[0-9]', password):
        return jsonify({"error": "Password must contain at least one number"}), 400

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return jsonify({"error": "Password must contain at least one special character"}), 400

    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt.encode(),
        iterations=100000
    ).hex()

    users[username] = {
        'email': email,
        'password': f"{salt}${password_hash}",
        'failed_attempts': 0
    }

    return jsonify({
        "message": "User registered successfully",
        "username": username
    }), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Missing request data"}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    if username not in users:
        return jsonify({"error": "Invalid credentials"}), 401

    user_data = users[username]
    stored_password = user_data['password']
    salt, hash_value = stored_password.split('$')

    provided_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt.encode(),
        iterations=100000
    ).hex()


    if provided_hash != hash_value:
        user_data['failed_attempts'] += 1
        return jsonify({"error": "Invalid credentials"}), 401

    user_data['failed_attempts'] = 0

    return jsonify({
        "message": "Login successful",
        "username": username
    })


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=False)
