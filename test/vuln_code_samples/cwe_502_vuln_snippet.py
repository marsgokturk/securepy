import pickle
from flask import Flask, request, jsonify

app = Flask(__name__)

profiles_db = {
    'user1': {'name': 'Alice', 'role': 'user'},
    'user2': {'name': 'Bob', 'role': 'admin'}
}

class UserProfile:
    def __init__(self, username, data):
        self.username = username
        self.data = data

    def get_profile_data(self):
        return profiles_db.get(self.username, {})


@app.route('/update_profile', methods=['POST'])
def update_profile():
    serialized_data = request.data
    try:
        user_profile = pickle.loads(serialized_data)
        if isinstance(user_profile, UserProfile) and user_profile.username in profiles_db:
            profiles_db[user_profile.username] = user_profile.data
            return jsonify({'status': 'Profile updated successfully'}), 200
        else:
            return jsonify({'error': 'Invalid user profile data'}), 400
    except pickle.UnpicklingError:
        return jsonify({'error': 'Deserialization error'}), 400


@app.route('/get_profile/<username>', methods=['GET'])
def get_profile(username):
    profile_data = profiles_db.get(username)
    if profile_data:
        return jsonify(profile_data), 200
    else:
        return jsonify({'error': 'Profile not found'}), 404


if __name__ == '__main__':
    app.run()