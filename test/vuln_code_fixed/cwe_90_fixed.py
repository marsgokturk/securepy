import os
import ldap
from ldap.filter import escape_filter_chars

class LDAPConnector:
    def __init__(self, server_uri, base_dn, user_dn, password):
        self.server_uri = server_uri
        self.base_dn = base_dn
        self.user_dn = user_dn
        self.password = password
        self.connection = None

    def connect(self):
        try:
            self.connection = ldap.initialize(self.server_uri)
            self.connection.simple_bind_s(self.user_dn, self.password)
            print("LDAP connection successful.")
        except ldap.LDAPError as e:
            print("LDAP connection failed. Please check your credentials/server settings.")
            raise

    def disconnect(self):
        if self.connection:
            try:
                self.connection.unbind_s()
                print("LDAP connection closed.")
            except ldap.LDAPError:
                print("Error closing LDAP connection.")
            finally:
                self.connection = None

    def search_by_street_address(self, address):
        try:
            if not isinstance(address, str) or len(address) > 100:
                print("Invalid input.")
                return

            sanitized_address = escape_filter_chars(address)
            search_filter = f"(StreetAddress={sanitized_address})"
            result = self.connection.search_s(
                self.base_dn,
                ldap.SCOPE_SUBTREE,
                search_filter,
                ['StreetAddress', 'cn', 'sn']
            )
            found = False
            for dn, entry in result:
                if dn:
                    print(f"Found entry: {entry}")
                    found = True
            if not found:
                print("No entries found.")
        except ldap.LDAPError:
            print("Search failed due to a server error.")

def main():
    server_uri = os.environ.get("LDAP_SERVER_URI")
    base_dn = os.environ.get("LDAP_BASE_DN")
    user_dn = os.environ.get("LDAP_USER_DN")
    password = os.environ.get("LDAP_PASSWORD")

    if not all([server_uri, base_dn, user_dn, password]):
        print("Missing LDAP configuration in environment variables.")
        print("Please set LDAP_SERVER_URI, LDAP_BASE_DN, LDAP_USER_DN, LDAP_PASSWORD.")
        return

    connector = LDAPConnector(server_uri, base_dn, user_dn, password)
    try:
        connector.connect()
        user_input = input("Enter the street address to search: ")
        connector.search_by_street_address(user_input)
    finally:
        connector.disconnect()

if __name__ == "__main__":
    main()