from flask import Flask, request, make_response, abort
from werkzeug.security import secure_filename

app = Flask(__name__)


@app.route('/login', methods=['POST'])
def login():
    account_id = request.form.get('account_id')

    if not account_id or not account_id.isdigit():
        abort(400)

    response = make_response("Logged in successfully!")
    response.set_cookie('accountID', secure_filename(account_id), httponly=True, secure=True)

    return response


if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'))