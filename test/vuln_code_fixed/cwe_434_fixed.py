import os
import io
import uuid
import magic
from flask import Flask, request, render_template_string, redirect, url_for, flash, send_from_directory
import werkzeug
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

app.secret_key = os.environ.get('FLASK_KEY')
if not app.secret_key:
    raise RuntimeError("FLASK_KEY environment variable not set")

MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB limit
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secure_uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_MIMETYPES = {
    'txt': 'text/plain',
    'pdf': 'application/pdf',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif'
}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_file_content(file_data, expected_extension):
    mime = magic.Magic(mime=True)
    file_mime = mime.from_buffer(file_data)
    expected_mime = ALLOWED_MIMETYPES.get(expected_extension.lower())

    if expected_mime is None:
        return False

    return file_mime == expected_mime


def generate_secure_filename(original_filename):
    if '.' not in original_filename:
        return None

    sanitized_filename = werkzeug.utils.secure_filename(original_filename)
    file_extension = sanitized_filename.rsplit('.', 1)[1].lower()

    secure_filename = f"{uuid.uuid4().hex}.{file_extension}"

    return secure_filename, file_extension


@app.route('/')
def upload_form():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Upload File</title>
    </head>
    <body>
        <h1>Upload a File</h1>
        <form action="{{ url_for('upload_file') }}" method="post" enctype="multipart/form-data">
            <input type="file" name="file"/><br/>
            <input type="submit" value="Upload"/>
        </form>
        <p>Maximum file size: 10MB</p>
        <p>Allowed file types: txt, pdf, png, jpg, jpeg, gif</p>
        {% with messages = get_flashed_messages() %}
        {% if messages %}
            <ul>
            {% for message in messages %}
                <li>{{ message }}</li>
            {% endfor %}
            </ul>
        {% endif %}
        {% endwith %}
    </body>
    </html>
    ''')


@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            flash('No file part')
            return redirect(url_for('upload_form'))

        file = request.files['file']

        if file.filename == '':
            flash('No selected file')
            return redirect(url_for('upload_form'))

        if not allowed_file(file.filename):
            flash('File type not allowed')
            return redirect(url_for('upload_form'))

        result = generate_secure_filename(file.filename)
        if not result:
            flash('Invalid filename')
            return redirect(url_for('upload_form'))

        secure_filename, file_extension = result

        file_data = file.read()

        if not validate_file_content(file_data, file_extension):
            flash('File content does not match the expected type')
            return redirect(url_for('upload_form'))

        file.seek(0)

        file_path = os.path.join(UPLOAD_FOLDER, secure_filename)
        file.save(file_path)

        flash('File successfully uploaded')
        return redirect(url_for('upload_form'))

    except werkzeug.exceptions.RequestEntityTooLarge:
        flash('File exceeds the maximum allowed size (10MB)')
        return redirect(url_for('upload_form'))
    except Exception as e:
        flash(f'File upload failed: {e}')
        return redirect(url_for('upload_form'))


@app.route('/files/<filename>')
def get_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


@app.errorhandler(413)
def request_entity_too_large(error):
    flash('File exceeds the maximum allowed size (10MB)')
    return redirect(url_for('upload_form'))


if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1')