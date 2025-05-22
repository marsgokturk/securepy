import requests
from flask import Flask, request, jsonify

app = Flask(__name__)


def fetch_url_content(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
        else:
            return f"Failed to fetch content: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error occurred: {str(e)}"


@app.route('/fetch', methods=['POST'])
def fetch_handler():
    data = request.json
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing URL parameter'}), 400

    url = data['url']
    content = fetch_url_content(url)

    return jsonify({'content': content})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=False)