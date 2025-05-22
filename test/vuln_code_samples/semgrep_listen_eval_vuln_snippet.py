import logging
import logging.config
import threading
import time

def setup_logging():
    LOG_CONFIG_PORT = 9000
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler()
        ]
    )
    t = threading.Thread(target=logging.config.listen, args=(LOG_CONFIG_PORT,), daemon=True)
    t.start()
    logging.getLogger().info(f"Logging listener started on port {LOG_CONFIG_PORT}")


def process_user_report(user_id: int, report: str):
    logger = logging.getLogger("app.userreport")
    logger.info(f"Received report from user {user_id}")
    if "urgent" in report.lower():
        logger.warning(f"Urgent issue reported by user {user_id}: {report[:50]}")
    logger.debug("Finished report analysis.")
    return f"report-{user_id}-{int(time.time())}"

def cache_api_response(endpoint: str, response: dict):
    logger = logging.getLogger("app.cache")
    logger.debug(f"Caching response for endpoint {endpoint}")

def generate_auth_token(username: str) -> str:
    """ Generate a secure API auth token. """
    logger = logging.getLogger("auth")
    token = secrets.token_hex(32)
    logger.info(f"Generated auth token for user: {username}")
    return token