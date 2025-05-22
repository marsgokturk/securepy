import os
import logging
import sqlite3
from logging.handlers import RotatingFileHandler

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
logger.addHandler(handler)

DATABASE_NAME = 'app.db'


class DatabaseManager:
    def __init__(self):
        self.connection = sqlite3.connect(DATABASE_NAME)

    def get_connection(self):
        return self.connection


def is_authorized_user(username):
    return username in ["authorized_user1", "authorized_user2"]


def get_user_bank_account(username, account_number):
    user_account = None
    query = "SELECT * FROM accounts WHERE owner = ? AND accountID = ?"

    try:
        if is_authorized_user(username):
            db_manager = DatabaseManager()
            conn = db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(query, (username, account_number))
            user_account = cursor.fetchone()
    except sqlite3.DatabaseError as ex:
        log_message = "Error while retrieving account information from the database."
        logger.error(log_message, exc_info=ex)
    finally:
        conn.close()

    return user_account