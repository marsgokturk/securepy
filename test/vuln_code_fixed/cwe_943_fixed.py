from defusedxml.ElementTree import fromstring
from flask import Flask, request, render_template_string, abort
import re
from users import xml_data

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('''
        <form action="/login" method="post">
        Username: <input name="username"><br>
        Password: <input name="password"><br>
        <input type="submit" value="Login">
        </form>
    ''')

@app.route('/login', methods=['POST'])
def login():
    def sanitize_input(user_input):
        if not re.match(r'^\w+$', user_input):
            return None
        return user_input

    username = sanitize_input(request.form.get('username', ''))
    password = sanitize_input(request.form.get('password', ''))

    if username is None or password is None:
        abort(400, description="Invalid input")

    try:
        root = fromstring(xml_data.data)
    except Exception:
        abort(500, description="XML data error")

    for user in root.findall(".//user"):
        login_elem = user.find("login")
        passwd_elem = user.find("password")
        if (login_elem is not None and passwd_elem is not None and
            login_elem.text == username and passwd_elem.text == password):

            home_dir_elem = user.find("home_dir")
            if home_dir_elem is not None:
                home_dir = home_dir_elem.text
                return f"Login successful! Home directory: {home_dir}"
            else:
                return "User found, but home directory missing!"
    return "Invalid credentials!"

if __name__ == '__main__':
    app.run(debug=False)