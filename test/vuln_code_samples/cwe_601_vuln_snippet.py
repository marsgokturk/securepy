import os
import logging
from flask import Flask, request, redirect, abort, url_for, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

app.config['DEBUG'] = os.environ.get('DEBUG', 'False').lower() == 'true'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-please-change-in-production')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/target')
def redirect_url():
    target_url = request.args.get('url')
    if not target_url:
        logger.warning("Redirect attempt with missing URL parameter")
        abort(400, description="Missing URL parameter")

    logger.info(f"Redirecting user to: {target_url}")
    return redirect(target_url)


@app.errorhandler(400)
def bad_request(error):
    return render_template('error.html', error=error), 400


@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error="Page not found"), 404


@app.errorhandler(500)
def server_error(error):
    logger.error(f"Server error: {error}")
    return render_template('error.html', error="Internal server error"), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '127.0.0.1')

    if app.config['DEBUG']:
        app.run(host=host, port=port, debug=True)
    else:
        # Production-like setup
        from waitress import serve

        logger.info(f"Starting production server on {host}:{port}")
        serve(app, host=host, port=port)