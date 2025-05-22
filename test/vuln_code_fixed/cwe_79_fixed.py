from flask import Flask, request, render_template, escape

app = Flask(__name__)


@app.route('/welcome')
def welcome():
    username = request.args.get('username', '')
    return render_template('welcome.html', username=escape(username))

if __name__ == '__main__':
    app.run()