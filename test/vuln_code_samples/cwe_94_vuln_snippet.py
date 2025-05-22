import socket

def start_server():
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()

        print(f"Server listening on {host}:{port}")

        while True:
            conn, addr = server_socket.accept()
            with conn:
                print(f"Connected by {addr}")
                data = conn.recv(1024).decode('utf-8')

                if not data:
                    break

                print(f"Received expression: {data}")

                try:
                    result = eval(data)
                    conn.sendall(f"Result: {result}".encode('utf-8'))
                except Exception as e:
                    conn.sendall(f"Error: {str(e)}".encode('utf-8'))

if __name__ == '__main__':
    start_server()