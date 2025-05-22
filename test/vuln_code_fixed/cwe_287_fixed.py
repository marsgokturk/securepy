from flask import Flask, request, redirect, session, make_response
from user_manager import UserManager
from datetime import timedelta
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

user_manager = UserManager()


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if user_manager.verify_user(username, password):
            session.permanent = True
            session['loggedin'] = True
            session['user'] = username
            session.modified = True
            return redirect('/admin')
        else:
            return 'Error: Invalid login', 401

    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''


@app.route('/admin')
def admin():
    if session.get('loggedin') and user_manager.is_admin(session.get('user')):
        return 'Welcome to the admin panel!'
    else:
        return 'Access denied', 403


if __name__ == '__main__':
    app.run(debug=False)