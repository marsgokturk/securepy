import os
from flask import Flask, request, redirect, url_for, render_template, flash
from flask_login import LoginManager, login_user, login_required, current_user
from models import db, User
from decimal import Decimal


def create_app(database_uri=None):
    app = Flask(__name__)
    app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_key')
    app.config['SQLALCHEMY_DATABASE_URI'] = database_uri or 'sqlite:///bank.db'
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('dashboard'))
            flash("Invalid credentials", "error")
        return render_template('login.html')

    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('dashboard.html', balance=current_user.balance)

    @app.route('/transfer', methods=['POST'])
    @login_required
    def transfer():
        recipient_username = request.form.get('recipient')
        amount_str = request.form.get('amount')

        if not recipient_username or not amount_str:
            flash("Recipient and amount are required", "error")
            return redirect(url_for('dashboard'))

        try:
            amount = Decimal(amount_str)
            sender = User.query.get(current_user.id)
            recipient = User.query.filter_by(username=recipient_username).first()

            if sender and recipient and sender.balance >= amount:
                sender.balance -= amount
                recipient.balance += amount
                db.session.commit()
                flash(f"Transferred {amount} to {recipient_username}", "success")
            else:
                flash("Transfer failed", "error")
        except Exception:
            db.session.rollback()
            flash("An error occurred", "error")

        return redirect(url_for('dashboard'))

    return app


if __name__ == '__main__':
    app = create_app()
    app.run()