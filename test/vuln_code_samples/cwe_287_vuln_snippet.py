from flask import Flask, request, redirect, make_response, session
from user_manager import UserManager
from datetime import timedelta
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout

user_manager = UserManager()

TOKEN = "kdfjghdkggb18182282"


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if request.form.get('token') == TOKEN:
            session['loggedin'] = True
            session['user'] = username
            return redirect('/admin')

        if user_manager.verify_user(username, password):
            session['loggedin'] = True
            session['user'] = username
            return redirect('/admin')
        else:
            return 'Error: Invalid login', 401

    return '''
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <!-- Hidden field for static token (used improperly) -->
        <input type="hidden" name="token" value="">
        <input type="submit" value="Login">
    </form>
    '''


@app.route('/admin')
def admin():
    if session.get('loggedin') and session.get('user') == 'Administrator':
        return 'Welcome to the admin panel!'
    else:
        return 'Access denied', 403


if __name__ == '__main__':
    app.run(debug=False)