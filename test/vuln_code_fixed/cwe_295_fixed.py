import ssl
import socket


def create_ssl_connection(hostname, port):
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            if cert is None:
                print("No certificate received from", hostname)
                return

            print("Certificate received from:", cert['subject'])
            print("Established connection with", hostname)
            print("Performing operations with the trusted host.")

if __name__ == "__main__":
    create_ssl_connection('example.com', 443)