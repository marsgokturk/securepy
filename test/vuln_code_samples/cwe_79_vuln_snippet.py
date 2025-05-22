from flask import Flask, request

app = Flask(__name__)

@app.route('/welcome')
def welcome():
    username = request.args.get('username', '')

    welcome_message = f'<div class="header">Welcome, {username}</div>'

    html_content = f'''
    <html>
        <head><title>Welcome</title></head>
        <body>
            {welcome_message}
            <p>Enjoy browsing our website!</p>
        </body>
    </html>
    '''

    return html_content

if __name__ == '__main__':
    app.run(debug=True)