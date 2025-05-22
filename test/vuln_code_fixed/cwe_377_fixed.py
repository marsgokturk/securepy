import socket
import tempfile
import os

def receive_and_write_to_temp_file(sock):
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file_name = temp_file.name
        try:
            while True:
                recvbuf = sock.recv(1024)
                if not recvbuf:
                    break
                temp_file.write(recvbuf)
            temp_file.flush()
            process_temp_file(temp_file_name)
        finally:
            os.remove(temp_file_name)

def process_temp_file(file_path):
    print(f"Processing temporary file at {file_path}")
    with open(file_path, 'rb') as file:
        data = file.read()
        print(f"Data length: {len(data)}")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 0))
        s.listen(1)
        print("Listening for connections...")
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            receive_and_write_to_temp_file(conn)

if __name__ == "__main__":
    main()