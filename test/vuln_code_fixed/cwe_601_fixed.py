import os
from flask import Flask, request, redirect, abort
from urllib.parse import urlparse

app = Flask(__name__)

ALLOWED_DOMAINS = [
    "example.com",
    "anotherexample.com"
]

def is_allowed_domain(netloc):
    netloc = netloc.lower().strip()
    for domain in ALLOWED_DOMAINS:
        domain = domain.lower()
        if netloc == domain or netloc.endswith("." + domain):
            return True
    return False

@app.route('/target')
def safe_redirect():
    target_url = request.args.get('url')
    if not target_url:
        abort(400, description="Missing URL parameter")
    parsed_url = urlparse(target_url)

    if parsed_url.scheme and parsed_url.netloc:
        if is_allowed_domain(parsed_url.netloc):
            return redirect(target_url)
        else:
            abort(400, description="Redirect to unauthorized domain is not allowed.")
    abort(400, description="Relative and local URL redirects are not allowed.")

if __name__ == '__main__':
   app.run()