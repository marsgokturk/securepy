from flask import Flask, request, make_response, redirect, url_for, jsonify
import uuid
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
active_sessions = {}


@app.route('/api/auth/login', methods=['POST'])
def login():
    """API endpoint for user authentication"""
    try:
        auth_data = request.get_json()

        if not auth_data:
            return jsonify({"error": "Missing authentication data"}), 400

        username = auth_data.get('username')
        password = auth_data.get('password')

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        if username and password:
            session_token = str(uuid.uuid4())
            active_sessions[session_token] = {
                'user_id': 'user_' + str(uuid.uuid4())[:8],
                'username': username
            }

            response = jsonify({
                "status": "success",
                "message": "Authentication successful"
            })

            response.set_cookie(
                'session_token',
                session_token,
                httponly=True,
                max_age=3600
            )

            return response
        else:
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({"status": "error", "message": "An error occurred during login"}), 500


@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    session_token = request.cookies.get('session_token')

    if not session_token or session_token not in active_sessions:
        return jsonify({"error": "Authentication required"}), 401

    session_data = active_sessions[session_token]

    return jsonify({
        "user_id": session_data['user_id'],
        "username": session_data['username'],
        "account_type": "premium"
    })


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session_token = request.cookies.get('session_token')

    if session_token and session_token in active_sessions:
        active_sessions.pop(session_token, None)

    response = jsonify({"status": "success", "message": "Logged out successfully"})
    response.delete_cookie('session_token')

    return response


if __name__ == '__main__':
    app.run()
