from flask import Flask, session, redirect, url_for, request
from datetime import timedelta
import os
import re

app = Flask(__name__)

secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    raise RuntimeError("SECRET_KEY environment variable not set.")
app.secret_key = secret_key

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)

def is_valid_username(username):
    return re.match("^[A-Za-z0-9_]+$", username)

@app.route('/')
def index():
    if 'user' in session:
        return f'Logged in as {session["user"]}'
    return 'You are not logged in.'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        if is_valid_username(username):
            session['user'] = username
            session.permanent = True
            return redirect(url_for('index'))
        else:
            return 'Invalid username.', 400
    return '''
    <form method="post">
        <p><input type=text name=username>
        <p><input type=submit value=Login>
    </form>
    '''

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=False)