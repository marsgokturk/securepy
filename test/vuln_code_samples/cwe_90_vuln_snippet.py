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
            print(f"LDAP connection failed: {e}")
            raise

    def disconnect(self):
        if self.connection:
            self.connection.unbind_s()
            print("LDAP connection closed.")

    def search_by_street_address(self, address):
        try:
            search_filter = f"(StreetAddress={address})"
            result = self.connection.search_s(self.base_dn, ldap.SCOPE_SUBTREE, search_filter)
            for dn, entry in result:
                if dn:
                    print(f"Found entry: {entry}")
        except ldap.LDAPError as e:
            print(f"Search failed: {e}")


def main():
    server_uri = "ldap://localhost:389"
    base_dn = "dc=example,dc=com"
    user_dn = "cn=admin,dc=example,dc=com"
    password = "password"

    connector = LDAPConnector(server_uri, base_dn, user_dn, password)

    try:
        connector.connect()
        user_input = input("Enter the street address to search: ")
        connector.search_by_street_address(user_input)
    finally:
        connector.disconnect()


if __name__ == "__main__":
    main()