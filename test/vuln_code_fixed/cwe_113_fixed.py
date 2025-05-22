from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import re

class HTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)

        author = query_params.get('author', [''])[0]
        sanitized_author = re.sub(r'[\r\n]', '', author)

        self.send_response(200)
        self.send_header('Set-Cookie', f'author={sanitized_author}')
        self.end_headers()

        self.wfile.write(b"<html><body>")
        self.wfile.write(b"<h1>Welcome to the Secure Blog!</h1>")
        self.wfile.write(b"</body></html>")

def run(server_class=HTTPServer, handler_class=HTTPRequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Running server on port {port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    run()