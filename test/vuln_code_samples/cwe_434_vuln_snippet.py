from flask import Flask, request, render_template_string, redirect, url_for, flash
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads/'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
    </body>
    </html>
    ''')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('upload_form'))

    file = request.files['file']

    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('upload_form'))

    file.save(os.path.join(UPLOAD_FOLDER, file.filename))
    flash('File successfully uploaded')
    return redirect(url_for('upload_form'))


if __name__ == '__main__':
    app.run(debug=True)