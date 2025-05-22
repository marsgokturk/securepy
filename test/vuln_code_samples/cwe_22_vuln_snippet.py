import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)


@app.route('/get-file')
def get_file():
    restricted_directory = "/var/www/user_files"

    filename = request.args.get('filename')

    if not filename:
        abort(400, description="Filename parameter is required.")

    filepath = os.path.join(restricted_directory, filename)

    try:
        if os.path.isfile(filepath):
            return send_file(filepath)
        else:
            abort(404, description="File not found.")
    except Exception as e:
        abort(500, description=str(e))


if __name__ == '__main__':
    app.run()