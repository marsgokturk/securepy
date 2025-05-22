import os
from flask import Flask, request, jsonify, render_template

from my_app.database import DatabaseManager
from my_app.analytics import AnalyticsEngine

app = Flask(__name__)

#
def configure_app(app):
    app.config["DB_URI"] = os.environ.get("DB_URI", "sqlite:///:memory:")
    app.config["ANALYTICS_KEY"] = os.environ.get("ANALYTICS_KEY")
    if not app.config["ANALYTICS_KEY"]:
        raise ValueError("Analytics key missing")

configure_app(app)
db = DatabaseManager(app.config["DB_URI"])
analytics = AnalyticsEngine(app.config["ANALYTICS_KEY"])

@app.route("/users/<int:user_id>")
def get_user(user_id):
    user = db.get_user(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    analytics.log_event("user_viewed", {"user_id": user_id})
    return jsonify(user)

@app.route("/")
def home():
    stats = analytics.get_site_stats()
    return render_template("home.html", stats=stats)

if __name__ == "__main__":
    app.run(debug=True)