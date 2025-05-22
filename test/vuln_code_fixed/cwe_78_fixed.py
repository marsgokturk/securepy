import re
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

GITHUB_REPO_PATTERN = re.compile(r'^[\w.-]+/[\w.-]+$')

def validate_input(repo_name):
    if not isinstance(repo_name, str) or len(repo_name) == 0:
        return False
    if not GITHUB_REPO_PATTERN.match(repo_name):
        return False
    return True

@app.route('/clone-repo', methods=['POST'])
def clone_repo():
    data = request.get_json()
    if not data or 'repository' not in data:
        return jsonify({'error': 'Invalid request, no repository specified'}), 400
    repo_name = data['repository']
    if not validate_input(repo_name):
        return jsonify({'error': 'Invalid repository name'}), 400
    repo_url = f"https://github.com/{repo_name}.git"
    try:
        subprocess.run(['git', 'clone', repo_url], check=True)
        return jsonify({'status': 'success'}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run()