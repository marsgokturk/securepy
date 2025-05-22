from flask import Flask, request, jsonify, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ.get('APP_KEY')


def get_db_connection():
    db_path = os.environ.get('DATABASE_PATH')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/document/<int:doc_id>', methods=['GET'])
def get_document(doc_id):
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Not authenticated"}), 401

    user_id = session['user_id']
    role = request.args.get('role', 'user')

    conn = get_db_connection()

    document = conn.execute('SELECT * FROM documents WHERE id = ?', (doc_id,)).fetchone()
    conn.close()

    if not document:
        return jsonify({"status": "error", "message": "Document not found"}), 404

    if document['owner_id'] == user_id or role == 'admin':
        return jsonify({
            "id": document['id'],
            "title": document['title'],
            "content": document['content'],
            "owner_id": document['owner_id'],
            "created_at": document['created_at']
        })

    return jsonify({"status": "error", "message": "Access denied"}), 403

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=False)
