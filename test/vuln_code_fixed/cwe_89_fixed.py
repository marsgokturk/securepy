import sqlite3
from flask import Flask, request, g

app = Flask(__name__)
DATABASE = 'app.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, itemname TEXT)')
        cursor.execute("INSERT INTO users (username, itemname) VALUES ('wiley', 'book1'), ('wiley', 'book2')")
        db.commit()

@app.route('/items', methods=['GET'])
def get_items():
    username = request.args.get('username')
    itemname = request.args.get('itemname')

    if not username or not itemname:
        return "Invalid input", 400

    query = "SELECT * FROM users WHERE username = ? AND itemname = ?"
    db = get_db()
    cursor = db.cursor()
    cursor.execute(query, (username, itemname))
    items = cursor.fetchall()

    return {'items': items}

if __name__ == '__main__':
    init_db()
    app.run()