import random
import sqlite3
import time
from hashlib import sha256

DATABASE = 'app.db'


class TokenManager:
    def __init__(self):
        self.conn = sqlite3.connect(DATABASE)
        self._ensure_tables_exist()

    def _ensure_tables_exist(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                user_id INTEGER PRIMARY KEY,
                session_token TEXT NOT NULL
            )
        ''')
        self.conn.commit()

    def generate_session_token(self, user_id):
        random.seed(time.time())
        random_number = random.randint(0, 1000000)
        token = sha256(f"{user_id}-{random_number}".encode()).hexdigest()
        return token

    def create_session(self, user_id):
        token = self.generate_session_token(user_id)
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        cursor.execute('INSERT INTO sessions (user_id, session_token) VALUES (?, ?)', (user_id, token))
        self.conn.commit()

    def validate_session(self, user_id, token):
        cursor = self.conn.cursor()
        cursor.execute('SELECT session_token FROM sessions WHERE user_id = ?', (user_id,))
        result = cursor.fetchone()
        return result is not None and result[0] == token

    def __del__(self):
        self.conn.close()


def login_user(user_id):
    token_manager = TokenManager()
    token_manager.create_session(user_id)
    print(f"Session created for user {user_id}")


def validate_user_session(user_id, token):
    token_manager = TokenManager()
    if token_manager.validate_session(user_id, token):
        print(f"User {user_id} session is valid")
    else:
        print(f"Invalid session for user {user_id}")

