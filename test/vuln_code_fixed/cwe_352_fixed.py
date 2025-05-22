from flask import Flask, request, jsonify, session, render_template, abort
import subprocess
import shlex
import json
import secrets
import os
import sys
from werkzeug.exceptions import BadRequest
import html
import logging
from pathlib import Path
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    if app.env == 'development':
        app.secret_key = secrets.token_hex(32)
    else:
        raise RuntimeError("SECRET_KEY environment variable not set")

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800
)


class User:
    def __init__(self, username):
        self.username = username

    def get_username(self):
        return self.username


class CommandExecutor:
    def __init__(self, user):
        self.user = user

    def execute_command(self, command):
        allowed_commands = ['ls', 'echo']
        try:
            if not command or not isinstance(command, str):
                return "Invalid command"

            if len(command) > 200:
                return "Command too long"

            args = shlex.split(command)
            if not args:
                return "No command provided"

            base_command = args[0]
            if base_command not in allowed_commands:
                logger.warning(f"Attempted execution of disallowed command: {base_command}")
                return "Command not allowed"

            if base_command == 'echo':
                sanitized_args = []
                sanitized_args.append(base_command)

                if len(args) > 10:
                    return "Too many arguments"

                for arg in args[1:]:
                    if not self._is_safe_argument(arg):
                        return "Invalid argument detected"
                    sanitized_args.append(arg)

                return self._run_subprocess(sanitized_args)

            elif base_command == 'ls':
                sanitized_args = []
                sanitized_args.append(base_command)

                allowed_dirs = ['.', './public', '/public']
                allowed_flags = ['-l', '-a', '-la', '-al']

                if len(args) == 1:
                    sanitized_args.append('.')
                else:
                    for arg in args[1:]:
                        if arg in allowed_flags:
                            sanitized_args.append(arg)
                            continue

                        if arg.startswith('-') and arg not in allowed_flags:
                            return "Flag not allowed"

                        path_arg = Path(arg)
                        path_str = str(path_arg)

                        if path_str.startswith('/'):
                            if not any(path_str.startswith(allowed_dir) for allowed_dir in allowed_dirs if
                                       allowed_dir.startswith('/')):
                                return f"Access to directory {path_str} is not allowed"

                        if '..' in path_str:
                            return "Directory traversal not allowed"

                        if not self._is_safe_path(path_str):
                            return "Invalid path detected"

                        sanitized_args.append(path_str)

                return self._run_subprocess(sanitized_args)

            return "Command not implemented"

        except subprocess.CalledProcessError:
            logger.error(f"Command execution failed")
            return "Command execution failed"
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out")
            return "Command execution timed out"
        except FileNotFoundError:
            logger.error(f"Command not found")
            return "Command not found"
        except Exception as ex:
            logger.error(f"An error occurred: {ex}")
            return "An error occurred during execution"

    def _is_safe_argument(self, arg):
        if not arg:
            return False

        if len(arg) > 100:
            return False

        forbidden_chars = ['&', ';', '|', '>', '<', '`', '$', '\\', '!']
        return not any(char in arg for char in forbidden_chars)

    def _is_safe_path(self, path):
        if not path:
            return False

        if len(path) > 100:
            return False

        safe_pattern = r'^[a-zA-Z0-9_\-\./]+$'
        return bool(re.match(safe_pattern, path))

    def _run_subprocess(self, sanitized_args):
        if not sanitized_args:
            return "No command to execute"

        result = subprocess.run(
            sanitized_args,
            shell=False,
            check=True,
            text=True,
            capture_output=True,
            timeout=5
        )
        return result.stdout


def load_user_data():
    user_data_file = Path('user_data.json')

    if not user_data_file.exists():
        logger.error("User data file not found")
        return User("default_user")

    try:
        with open(user_data_file, 'r') as file:
            data = json.load(file)

            if not isinstance(data, dict):
                logger.error("Invalid user data format: not a dictionary")
                return User("default_user")

            if 'username' not in data:
                logger.error("Invalid user data format: missing username")
                return User("default_user")

            if not isinstance(data['username'], str):
                logger.error("Invalid user data format: username is not a string")
                return User("default_user")

            username = data['username']
            if len(username) > 50:
                logger.error("Username too long")
                return User("default_user")

            if not re.match(r'^[a-zA-Z0-9_\-\.]+$', username):
                logger.error("Username contains invalid characters")
                return User("default_user")

            return User(username)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in user data file: {e}")
        return User("default_user")
    except IOError as e:
        logger.error(f"Error reading user data file: {e}")
        return User("default_user")


@app.route('/', methods=['GET'])
def index():
    csrf_token = secrets.token_hex(32)
    session['csrf_token'] = csrf_token

    return render_template('index.html', csrf_token=csrf_token)


@app.route('/execute', methods=['POST'])
def execute():
    try:
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or not secrets.compare_digest(csrf_token, session.get('csrf_token', '')):
            logger.warning("CSRF token validation failed")
            return jsonify({'error': 'Invalid request'}), 403

        command = request.form.get('command')
        if not command:
            return jsonify({'error': 'No command provided'}), 400

        if len(command) > 200:
            return jsonify({'error': 'Command too long'}), 400

        user = load_user_data()
        executor = CommandExecutor(user)
        output = executor.execute_command(command)

        sanitized_output = html.escape(output)

        return jsonify({'result': sanitized_output})
    except BadRequest as e:
        logger.error(f"Bad request: {e}")
        return jsonify({'error': 'Invalid request data'}), 400
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'error': 'Page not found'}), 404


@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)