import os
from flask import Flask, request, send_file, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.route('/get-file')
def get_file():
    restricted_directory = "/var/www/user_files"
    filename = request.args.get('filename')
    if not filename:
        abort(400, description="Filename parameter is required.")

    safe_filename = secure_filename(filename)
    if not safe_filename:
        abort(400, description="Invalid filename.")

    abs_restricted_directory = os.path.abspath(restricted_directory)
    abs_filepath = os.path.abspath(os.path.join(abs_restricted_directory, safe_filename))

    if not abs_filepath.startswith(abs_restricted_directory + os.sep):
        abort(400, description="Illegal file path.")

    try:
        if os.path.isfile(abs_filepath):
            return send_file(abs_filepath)
        else:
            abort(404, description="File not found.")
    except Exception as e:
        abort(500, description=str(e))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)