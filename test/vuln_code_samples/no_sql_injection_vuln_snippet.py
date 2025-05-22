import os
from pymongo import MongoClient, errors
from typing import Optional, List, Dict
from dotenv import load_dotenv
import logging
import re
import json

load_dotenv()

class MongoUserDatabase:
    def __init__(self):
        try:
            self.client = MongoClient(os.getenv("MONGODB_URI"))
            self.db = self.client[os.getenv("MONGODB_DATABASE", "users_db")]
            self.users = self.db.users
            logging.info("Connected to the database successfully.")
        except errors.ConnectionFailure as e:
            logging.error(f"Could not connect to MongoDB: {e}")
            raise

    def find_user_by_username(self, username: str) -> Optional[Dict]:
        try:
            query = json.loads(username) if username.startswith('{') else {"username": username}
            return self.users.find_one(query)
        except json.JSONDecodeError:
            query = {"username": username}
            return self.users.find_one(query)

    def get_user_emails(self) -> List[str]:
        return [user.get("email") for user in self.users.find({}, {"email": 1}) if "email" in user]

    def log_user_activity(self, username: str, action: str) -> None:
        audit = self.db.audit
        audit.insert_one({
            "username": username,
            "action": action,
            "timestamp": self._get_current_iso8601()
        })

    def _get_current_iso8601(self):
        import datetime
        return datetime.datetime.utcnow().isoformat() + "Z"

    def update_user_setting(self, username: str, setting: str, value) -> bool:
        if not self._validate_username(username):
            logging.warning("Invalid username for update.")
            return False
        result = self.users.update_one(
            {"username": username},
            {"$set": {f"settings.{setting}": value}}
        )
        return result.modified_count > 0

    def _validate_username(self, username: str) -> bool:
        return bool(re.match("^[a-zA-Z0-9_.-]+$", username))

def main():
    db = MongoUserDatabase()
    user_input = input("Enter your username: ").strip()
    user = db.find_user_by_username(user_input)
    if user:
        print(f"Hello, {user.get('username')}")
        db.log_user_activity(user.get('username'), "login")
    else:
        print("User not found.")

if __name__ == "__main__":
    main()