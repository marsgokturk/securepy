from flask import Flask, request, jsonify, session, redirect, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATABASE = 'app.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price REAL NOT NULL
            )
        ''')
        cursor = conn.execute("SELECT * FROM users WHERE username = ?", ('admin',))
        if cursor.fetchone() is None:
            hashed = generate_password_hash('adminpass')
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', hashed))
        cursor2 = conn.execute("SELECT * FROM products WHERE name = ?", ('Widget',))
        if cursor2.fetchone() is None:
            conn.execute('INSERT INTO products (name, price) VALUES (?, ?)', ('Widget', 25.00))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = get_db()
    try:
        cursor = conn.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return jsonify({"message": "Logged in successfully"}), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    finally:
        conn.close()

@app.route('/logout')
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'}), 200

@app.route('/admin/add_product', methods=['POST'])
def add_product():
    try:
        name = request.form['name']
        price = float(request.form['price'])
        conn = get_db()
        with conn:
            conn.execute('INSERT INTO products (name, price) VALUES (?, ?)', (name, price))
        return jsonify({"message": "Product added successfully"}), 201
    except Exception as e:
        return jsonify({"error": "Unable to add product"}), 500

@app.route('/admin/delete_product/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    try:
        conn = get_db()
        with conn:
            conn.execute('DELETE FROM products WHERE id = ?', (product_id,))
        return jsonify({"message": "Product deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": "Something unexpected happened"}), 500

@app.route('/admin/list_products', methods=['GET'])
def list_products():
    conn = get_db()
    try:
        cursor = conn.execute('SELECT id, name, price FROM products')
        products = [dict(row) for row in cursor.fetchall()]
        return jsonify(products), 200
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    app.run()