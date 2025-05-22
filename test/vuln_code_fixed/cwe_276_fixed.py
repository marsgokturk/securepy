import os
import sys
import logging
import tempfile
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def process_user_data(user_id: str, data: str) -> str:
    logger.info(f"Processing data for user: {user_id}")
    return data.upper()


def store_data_file(data: str, base_dir: str = "/tmp") -> str:
    try:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        archive_filename = os.path.join(base_dir, f"user_data_{timestamp}.txt")
        with open(archive_filename, "w") as f:
            f.write(data)
        os.chmod(archive_filename, 0o600)
        return archive_filename
    except Exception as e:
        logger.error(f"Failed to store data: {e}")
        sys.exit(1)


def validate_input(user_id: str, data: str) -> bool:
    if not user_id.isalnum():
        logger.error("Invalid user ID. It must be alphanumeric.")
        return False
    if not data:
        logger.error("Data is empty.")
        return False
    return True


def random_temp_file(data: str) -> str:
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
        tmp.write(data)
        path = tmp.name
    logger.info(f"Temp file created at {path}")
    os.chmod(path, 0o600)
    return path


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <user_id> <data>")
        sys.exit(1)

    user_id = sys.argv[1]
    data = sys.argv[2]

    if not validate_input(user_id, data):
        sys.exit(1)

    processed = process_user_data(user_id, data)
    file_path = store_data_file(processed)
    temp = random_temp_file(data)


if __name__ == "__main__":
    main()