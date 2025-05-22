import sqlite3
import sys
import secrets


class SessionManager:
    def __init__(self):
        self.conn = sqlite3.connect(':memory:')
        self._setup_database()

    def _setup_database(self):
        cursor = self.conn.cursor()
        cursor.execute('''CREATE TABLE sessions (user_id INTEGER, token TEXT)''')
        self.conn.commit()

    def generate_session_token(self):
        token = secrets.token_hex(16)
        return token

    def create_session(self, user_id):
        token = self.generate_session_token()
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO sessions (user_id, token) VALUES (?, ?)', (user_id, token))
        self.conn.commit()
        print(f"Session created for user {user_id} with token: {token}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <user_id>")
        sys.exit(1)

    try:
        user_id = int(sys.argv[1])
    except ValueError:
        print("User ID must be an integer.")
        sys.exit(1)

    session_manager = SessionManager()
    session_manager.create_session(user_id=user_id)


if __name__ == "__main__":
    main()