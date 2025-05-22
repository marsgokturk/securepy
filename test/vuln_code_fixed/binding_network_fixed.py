import os
import socket
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import sqlite3

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("myapp.server")

class UserManager:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, last_login DATETIME)"
        )
        self.lock = threading.Lock()

    def add_user(self, username):
        with self.lock, self.conn:
            try:
                self.conn.execute(
                    "INSERT INTO users (username, last_login) VALUES (?, ?)", (username, datetime.now())
                )
            except sqlite3.Error as e:
                logger.error(f"Database error: {e}")

    def update_login(self, username):
        with self.lock, self.conn:
            try:
                self.conn.execute(
                    "UPDATE users SET last_login = ? WHERE username = ?", (datetime.now(), username)
                )
            except sqlite3.Error as e:
                logger.error(f"Database error: {e}")

    def list_users(self):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id, username, last_login FROM users")
            return cur.fetchall()

def handle_client(conn, addr, user_manager):
    try:
        conn.sendall(b"Enter your username: ")
        username = conn.recv(1024).decode("utf-8").strip()
        if len(username) > 0:
            user_manager.update_login(username)
            msg = f"Welcome back, {username}!\n"
        else:
            anonymous = f"guest_{addr[1]}"
            user_manager.add_user(anonymous)
            msg = f"New user registered as {anonymous}\n"
        conn.sendall(msg.encode("utf-8"))
    except Exception as e:
        logger.exception(f"Exception during client handling: {e}")
    finally:
        conn.close()

def get_secret_key():
    secret_key = os.environ.get("MYAPP_SECRET_KEY")
    if not secret_key:
        raise RuntimeError("Secret key not set in environment.")
    return secret_key

def start_server(host="127.0.0.1", port=9000):
    user_manager = UserManager(":memory:")
    secret_key = get_secret_key()
    max_threads = 10
    connection_queue = 10

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(connection_queue)

        logger.info(f"Server started on {host}:{port}")
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            while True:
                conn, addr = server_socket.accept()
                if len(executor._threads) < max_threads:
                    executor.submit(handle_client, conn, addr, user_manager)
                else:
                    logger.warning(f"Max thread count reached, connection from {addr} refused.")
                    conn.close()

def send_welcome_email(user_email):
    logger.info(f"Sending welcome email to {user_email}")

def audit_log(event, user=None):
    logger.info(f"AUDIT: {event} for user={user}")

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested. Exiting...")