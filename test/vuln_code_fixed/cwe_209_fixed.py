import logging
import sqlite3

logging.basicConfig(filename='app.log', level=logging.ERROR)


class BankAccount:
    def __init__(self, owner, account_id, balance):
        self.owner = owner
        self.account_id = account_id
        self.balance = balance


class BankManager:
    def __init__(self, database_path):
        self.database_path = database_path

    def is_authorized_user(self, username):
        return True

    def get_user_bank_account(self, username, account_number):
        user_account = None
        try:
            if self.is_authorized_user(username):
                conn = sqlite3.connect(self.database_path)
                cursor = conn.cursor()
                query = "SELECT * FROM accounts WHERE owner=? AND accountID=?"
                cursor.execute(query, (username, account_number))
                account_data = cursor.fetchone()
                if account_data:
                    user_account = BankAccount(account_data[0], account_data[1], account_data[2])
                conn.close()
        except sqlite3.DatabaseError as ex:
            log_message = "A database error occurred during account retrieval."
            logging.error(log_message)

        return user_account