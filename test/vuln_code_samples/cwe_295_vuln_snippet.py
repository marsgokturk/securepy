import requests
from flask import Flask, request, jsonify, abort
from datetime import datetime, timedelta
import re

app = Flask(__name__)

class UserService:
    def __init__(self):
        self.users = {"alice": {"balance": 1000, "last_access": datetime.now()}}

    def get_user_balance(self, username):
        user = self.users.get(username)
        if user:
            if datetime.now() - user["last_access"] < timedelta(minutes=5):
                return user["balance"]
            else:
                app.logger.warning(f"Access expired for user {username}")
        else:
            app.logger.warning(f"User {username} not found")
        return None

user_service = UserService()

class ExternalApiService:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def fetch_data(self, endpoint):
        if not re.fullmatch(r'[A-Za-z0-9_-]+', endpoint):
            app.logger.error("Invalid endpoint name.")
            raise ValueError("Invalid endpoint.")
        url = f"{self.base_url}/{endpoint}"
        try:
            response = requests.get(url, timeout=5, verify=False)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            app.logger.error(f"Error fetching data: {e}")
            return None

@app.route('/user/<username>/balance', methods=['GET'])
def get_balance(username):
    if not re.fullmatch(r'\w+', username):
        abort(400, description="Invalid username format.")
    balance = user_service.get_user_balance(username)
    if balance is not None:
        return jsonify({"username": username, "balance": balance}), 200
    return jsonify({"error": "User not found or access expired"}), 404

@app.route('/external-data', methods=['GET'])
def external_data():
    api_service = ExternalApiService(base_url='https://api.example.com')
    try:
        data = api_service.fetch_data('data-endpoint')
        if data:
            return jsonify(data), 200
        return jsonify({"error": "Failed to fetch external data"}), 500
    except ValueError:
        return jsonify({"error": "Invalid API endpoint requested."}), 400

if __name__ == '__main__':
    app.run()