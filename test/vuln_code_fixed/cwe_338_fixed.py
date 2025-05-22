import os
from hashlib import sha256

class TokenGenerator:
    def __init__(self):
        pass

    def generate_secure_token(self, user_id):
        random_bytes = os.urandom(16)
        token = sha256(f"{user_id}{random_bytes.hex()}".encode()).hexdigest()
        return token

class UserService:
    def __init__(self):
        self.tokens = {}

    def create_user_session(self, user_id):
        token_generator = TokenGenerator()
        token = token_generator.generate_secure_token(user_id)
        self.tokens[user_id] = token
        print(f"Generated token for user {user_id}: {token}")

    def validate_token(self, user_id, token):
        return self.tokens.get(user_id) == token

def run(user_id):
    user_service = UserService()
    user_service.create_user_session(user_id)
    token = input("Enter the token to validate: ")
    if user_service.validate_token(user_id, token):
        print("Token validated successfully!")
    else:
        print("Invalid token!")