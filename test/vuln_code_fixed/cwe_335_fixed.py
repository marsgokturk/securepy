import os

class AccountManager:
    def __init__(self):
        self.accounts = {}

    def generate_account_id(self):
        return int.from_bytes(os.urandom(4), 'big')

    def create_account(self, username):
        if username in self.accounts:
            raise ValueError("Account already exists")
        account_id = self.generate_account_id()
        self.accounts[username] = account_id
        return account_id

    def get_account_id(self, username):
        return self.accounts.get(username, None)