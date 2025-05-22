import os
import hmac
import hashlib
import json
import base64
import sqlite3
from twisted.internet import protocol, reactor

SECRET_KEY_ENV_VAR = os.environ.get("SECRET_KEY_ENV_VAR")

def check_hmac(signature, data, secret_key):
    computed_hmac = hmac.new(secret_key.encode(), data.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed_hmac, signature)

def getSecretKey():
    secret_key = os.getenv(SECRET_KEY_ENV_VAR)
    if not secret_key:
        raise RuntimeError("Secret key not found in environment")
    return secret_key

def log_auth_attempt(success, user_data):
    if user_data:
        user_data = base64.b64encode(user_data.encode()).decode()  # Encode to prevent injection
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO auth_logs (status, user_data) VALUES (?, ?)',
                   ('success' if success else 'failure', user_data))
    conn.commit()
    conn.close()

class AuthFail(Exception):
    pass

class ExampleProtocol(protocol.Protocol):
    def dataReceived(self, data):
        headers = self.parse_data(data)
        self.confirmAuth(headers)

    def parse_data(self, data):
        extracted_data = self.extract_user_data(data)
        signature = hmac.new(getSecretKey().encode(), extracted_data.encode(), hashlib.sha256).hexdigest()
        return {
            'AuthToken': base64.b64encode(json.dumps({'signature': signature, 'data': extracted_data}).encode()).decode()
        }

    def extract_user_data(self, data):
        return data.decode()

    def confirmAuth(self, headers):
        try:
            token = json.loads(base64.b64decode(headers['AuthToken']).decode())
            if not check_hmac(token['signature'], token['data'], getSecretKey()):
                log_auth_attempt(False, token['data'])
                raise AuthFail("Authentication failed.")
            self.secure_data = token['data']
            log_auth_attempt(True, token['data'])
        except Exception as e:
            log_auth_attempt(False, str(e))
            raise AuthFail("Authentication failed") from e

def initialize_database():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS auth_logs (id INTEGER PRIMARY KEY, status TEXT, user_data TEXT)')
    conn.commit()
    conn.close()

def main():
    initialize_database()
    factory = protocol.ServerFactory()
    factory.protocol = ExampleProtocol
    reactor.listenTCP(8000, factory)
    reactor.run()

if __name__ == "__main__":
    main()