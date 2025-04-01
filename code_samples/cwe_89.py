import sqlite3
from flask import Flask, request

app = Flask(__name__)

def get_current_user_id_from_context():
    return request.headers.get("X-User-ID")

@app.route("/inventory")
def fetch_inventory():
    item_name = request.args.get("item")
    user_id = get_current_user_id_from_context()

    if not item_name or not user_id:
        return {"error": "Missing parameters"}, 400

    query = f"""
        SELECT * FROM inventory 
        WHERE user_id = '{user_id}' AND item_name = '{item_name}'
    """

    conn = sqlite3.connect("inventory.db")
    cursor = conn.cursor()
    cursor.execute(query)  # 🔥 vulnerable to SQL injection
    rows = cursor.fetchall()
    conn.close()

    return {"results": rows}

if __name__ == "__main__":
    app.run(debug=True)