import logging
import logging.config
import secrets
import os


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        handlers=[
            logging.StreamHandler()
        ]
    )

    config_file = os.environ.get('LOG_CONFIG_FILE', '')
    if config_file and os.path.exists(config_file):
        try:
            logging.config.fileConfig(
                config_file,
                disable_existing_loggers=False
            )
            logging.getLogger().info(f"Logging configuration loaded from {config_file}")
        except Exception as e:
            logging.getLogger().error(f"Failed to load logging configuration: {e}")
    else:
        logging.getLogger().info("Using default logging configuration")


def process_user_report(user_id: int, report: str):
    if not isinstance(user_id, int) or user_id <= 0:
        logging.getLogger("app.security").warning(f"Invalid user_id format in report: {type(user_id)}")
        return None

    logger = logging.getLogger("app.userreport")
    sanitized_user_id = str(user_id)
    logger.info(f"Received report from user {sanitized_user_id}")
    if report and "urgent" in report.lower():
        logger.warning(f"Urgent issue reported by user {sanitized_user_id}")

    logger.debug("Finished report analysis")
    report_id = f"report-{sanitized_user_id}-{secrets.token_hex(8)}"
    return report_id


def cache_api_response(endpoint: str, response: dict):
    if not endpoint or not isinstance(endpoint, str):
        return

    logger = logging.getLogger("app.cache")
    sanitized_endpoint = endpoint.replace('\n', '').replace('\r', '')[:100]
    logger.debug(f"Caching response for endpoint {sanitized_endpoint}")
    logger.debug(f"Response size: {len(str(response)) if response else 0} bytes")


def generate_auth_token(username: str) -> str:
    if not username or not isinstance(username, str):
        logging.getLogger("app.security").warning("Auth token requested with invalid username")
        return ""

    logger = logging.getLogger("auth")
    token = secrets.token_hex(32)
    logger.info(f"Auth token generated for user")
    username_hash = hash(username) % 10000
    logger.debug(f"Token generation completed for user hash: {username_hash}")

    return token


def reload_logging_config():
    config_file = os.environ.get('LOG_CONFIG_FILE', '')
    if config_file and os.path.exists(config_file):
        try:
            logging.config.fileConfig(
                config_file,
                disable_existing_loggers=False
            )
            logging.getLogger().info(f"Logging configuration reloaded from {config_file}")
            return True
        except Exception as e:
            logging.getLogger().error(f"Failed to reload logging configuration: {e}")
            return False
    else:
        logging.getLogger().warning("No configuration file specified for reload")
        return False