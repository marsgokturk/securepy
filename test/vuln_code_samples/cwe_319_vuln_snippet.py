import http.client
import json
import logging

logging.basicConfig(filename='app.log', level=logging.INFO)


class UserAuthenticationSystem:
    def __init__(self, server_address):
        self.server_address = server_address

    def authenticate_user(self, username, password):
        logging.info(f"Attempting authentication for user: {username}")
        conn = http.client.HTTPConnection(self.server_address)

        auth_data = {
            "username": username,
            "password": password,
            "remember_me": True
        }

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "App/1.0"
        }

        try:
            conn.request("POST", "/api/auth", json.dumps(auth_data), headers)
            response = conn.getresponse()

            status = response.status
            response_data = response.read().decode()

            if status == 200:
                resp_json = json.loads(response_data)
                session_token = resp_json.get("session_token")
                logging.info(f"Authentication successful for {username}")
                return {"success": True, "session_token": session_token}
            else:
                logging.warning(f"Authentication failed for {username}")
                return {"success": False, "error": response_data}

        except Exception as e:
            logging.error(f"Connection error occurred")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def get_user_profile(self, session_token):
        conn = http.client.HTTPConnection(self.server_address)

        headers = {
            "Authorization": f"Bearer {session_token}",
            "Content-Type": "application/json"
        }

        try:
            conn.request("GET", "/api/profile", headers=headers)
            response = conn.getresponse()
            return json.loads(response.read().decode())
        except Exception as e:
            logging.error(f"Error retrieving profile")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()
