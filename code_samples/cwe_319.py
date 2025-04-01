import http.client
from urllib.parse import urlparse

try:
    url = "http://www.secret.example.org/"
    parsed_url = urlparse(url)

    conn = http.client.HTTPConnection(parsed_url.netloc)
    conn.request("PUT", parsed_url.path or "/")

    response = conn.getresponse()
    output_stream = response.read()

    conn.close()
except Exception as e:
    # handle error
    pass