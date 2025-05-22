from flask import Flask, request, session, abort, make_response, escape
import os
from db_connect import get_user_role, display_medical_history, check_patient_permission
import re
import logging
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import bleach

app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    if os.environ.get('FLASK_ENV') == 'development':
        app.secret_key = os.urandom(24)
        logging.warning("Using temporary secret key - NOT SECURE FOR PRODUCTION")
    else:
        raise RuntimeError("No SECRET_KEY set in environment")

# Session security settings
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800

csrf = CSRFProtect(app)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

talisman = Talisman(
    app,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self'",
    },
    force_https=True
)

logging.basicConfig(
    filename='medical_access.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

ALLOWED_ROLES = ['Doctor', 'Nurse', 'Reader', 'Admin']


@app.route('/view_medical_record', methods=['POST'])
@limiter.limit("15 per minute")
def view_medical_record():
    if 'user_id' not in session:
        logging.warning(f"Unauthenticated access attempt from IP: {request.remote_addr}")
        abort(401)

    username = bleach.clean(request.form.get('username', ''))
    patient_id = bleach.clean(request.form.get('patient_ID', ''))

    if not username or not patient_id:
        logging.warning(f"Missing required fields from user: {session.get('user_id')}")
        abort(400)

    if not validate_input(username) or not validate_input(patient_id):
        logging.warning(f"Invalid input format from user: {session.get('user_id')}")
        abort(400)

    stored_user_id = session.get('user_id')

    role = session.get('role')
    if not role:
        role = get_user_role(stored_user_id)
        if role:
            session['role'] = role
        else:
            logging.error(f"Authentication error for user_id: {stored_user_id}")
            abort(403)

    if role not in ALLOWED_ROLES:
        log_access_attempt(stored_user_id, patient_id, False, "Invalid role")
        abort(403)

    if role == 'Reader':
        if not has_permission_for_patient(stored_user_id, patient_id):
            log_access_attempt(stored_user_id, patient_id, False, "Insufficient permission")
            abort(403)
    elif role == 'Doctor' or role == 'Nurse':
        if not has_clinical_permission_for_patient(stored_user_id, patient_id, role):
            log_access_attempt(stored_user_id, patient_id, False, "Insufficient clinical permission")
            abort(403)
    elif role == 'Admin':
        if not has_admin_permission():
            log_access_attempt(stored_user_id, patient_id, False, "Admin access outside permitted time")
            abort(403)
    else:
        log_access_attempt(stored_user_id, patient_id, False, "Role not authorized")
        abort(403)

    log_access_attempt(stored_user_id, patient_id, True, "Access granted")

    try:
        history = display_medical_history(patient_id)
        response = make_response(history)
        return response
    except Exception as e:
        logging.error(f"Error retrieving medical history: {str(e)}")
        abort(500)


def validate_input(value):
    if not value:
        return False
    pattern = re.compile(r'^[a-zA-Z0-9_\-\.]+$')
    return bool(pattern.match(value))


def has_permission_for_patient(user_id, patient_id):

    return check_patient_permission(user_id, patient_id, 'read')


def has_clinical_permission_for_patient(user_id, patient_id, role):

    return check_patient_permission(user_id, patient_id, role.lower())


def has_admin_permission():

    import datetime
    now = datetime.datetime.now()
    weekday = now.weekday()
    hour = now.hour

    return weekday < 5 and 8 <= hour < 18


def log_access_attempt(user_id, patient_id, success, reason=""):
    """
    Log all access attempts for audit purposes using proper logging
    """
    if success:
        logging.info(f"AUTHORIZED: User {user_id} accessed Patient {patient_id}")
    else:
        logging.warning(f"UNAUTHORIZED: User {user_id} attempted to access Patient {patient_id}. Reason: {reason}")


@app.errorhandler(400)
def bad_request(e):
    return "Bad Request", 400


@app.errorhandler(401)
def unauthorized(e):
    return "Authentication required", 401


@app.errorhandler(403)
def forbidden(e):
    return "Access denied", 403


@app.errorhandler(500)
def server_error(e):
    return "Internal server error", 500


if __name__ == '__main__':
    app.run(debug=False, host="127.0.0.1", port=8080)