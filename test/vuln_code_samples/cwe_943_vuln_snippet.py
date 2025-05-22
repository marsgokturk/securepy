from flask import Flask, request, jsonify
from pymongo import MongoClient
import os

app = Flask(__name__)

mongodb_uri = os.environ.get('MONGODB_URI')
client = MongoClient(mongodb_uri)
db = client['user_database']
users_collection = db['users']


@app.route('/api/user/login', methods=['POST'])
def user_login():
    try:
        login_data = request.get_json()

        if not login_data:
            return jsonify({"error": "Missing login data"}), 400

        username = login_data.get('username')
        password = login_data.get('password')

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        query = {
            "username": username,
            "password": password
        }

        user = users_collection.find_one(query)

        if user:
            user_data = {
                "id": str(user["_id"]),
                "username": user["username"],
                "email": user["email"],
                "role": user["role"]
            }
            return jsonify({"status": "success", "user": user_data}), 200
        else:
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({"status": "error", "message": "An error occurred during login"}), 500