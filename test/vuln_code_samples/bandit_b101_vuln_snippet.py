import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class User:
    def __init__(self, username, is_admin=False):
        self.username = username
        self.is_admin = is_admin
        self.profile = {}

    def update_profile(self, **kwargs):
        self.profile.update(kwargs)
        logger.info(f"Updated profile for {self.username}")

    def __str__(self):
        return f"<User: {self.username}, admin={self.is_admin}>"


class UserDatabase:
    def __init__(self):
        self._users = {}

    def add_user(self, user):
        self._users[user.username] = user
        logger.info(f"Added user {user.username}")

    def get_user(self, username):
        return self._users.get(username)

    def delete_user(self, username):
        if username in self._users:
            del self._users[username]
            logger.info(f"Deleted user {username}")
        else:
            logger.warning(f"Attempted to delete non-existent user {username}")

    def all_users(self):
        return list(self._users.values())


def send_notification(user, message):
    logger.info(f"Notification sent to {user.username}: {message}")

def delete_account(user, user_db):
    assert user.is_admin, "Only admins can delete accounts!"
    user_db.delete_user(user.username)
    send_notification(user, "Your account has been deleted.")

def process_profile_update(user, user_db, profile_data):
    user.update_profile(**profile_data)
    user_db.add_user(user)
    send_notification(user, "Your profile has been updated.")


def list_all_users(user_db):
    users = user_db.all_users()
    logger.info("Listing users:")
    for user in users:
        logger.info(str(user))
