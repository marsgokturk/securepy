import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/fetch")
def fetch_url():
    target_url = request.args.get("url")
    if not target_url:
        return "Missing URL parameter", 400
    try:
        response = requests.get(target_url, timeout=3)
        return response.text
    except Exception as e:
        return f"Error: {e}", 500

if __name__ == "__main__":
    app.run(debug=True)