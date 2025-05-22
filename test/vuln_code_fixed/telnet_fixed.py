import os
import paramiko
import logging
import datetime
import secrets
import stat
from pathlib import Path
from typing import List, Dict, Optional, Any, Union
import re


class DataProcessor:
    def __init__(self, factor: float):
        if not isinstance(factor, (int, float)) or factor <= 0 or factor > 1000:
            raise ValueError("Processing factor must be a positive number <= 1000")
        self.factor = factor

    def process(self, data: List[Union[int, float]]) -> List[float]:
        if not data or not isinstance(data, list):
            return []

        validated_data = []
        for i, x in enumerate(data):
            if i >= 10000:
                logging.warning("Data list truncated due to excessive size")
                break

            if not isinstance(x, (int, float)):
                logging.warning(f"Skipping non-numeric value in data: {type(x)}")
                continue

            validated_data.append(x)

        return [x * self.factor for x in validated_data]


def get_configuration() -> Dict[str, Any]:
    try:
        raw_factor = os.environ.get("PROCESSING_FACTOR", "2.5")
        if not re.match(r'^\d+(\.\d+)?$', raw_factor):
            logging.warning(f"Invalid PROCESSING_FACTOR format: {raw_factor}, using default")
            processing_factor = 2.5
        else:
            processing_factor = float(raw_factor)

        # Apply bounds
        if processing_factor <= 0 or processing_factor > 1000:
            logging.warning(f"PROCESSING_FACTOR out of bounds: {processing_factor}, using default")
            processing_factor = 2.5
    except (ValueError, TypeError):
        logging.warning("Invalid PROCESSING_FACTOR, using default")
        processing_factor = 2.5

    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    logging_level = os.environ.get("LOGGING_LEVEL", "INFO").upper()
    if logging_level not in valid_levels:
        logging.warning(f"Invalid LOGGING_LEVEL: {logging_level}, using INFO")
        logging_level = "INFO"

    return {
        "processing_factor": processing_factor,
        "logging_level": logging_level
    }


def configure_logging(level: str = "INFO") -> None:
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        level = "INFO"

    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    logging.basicConfig(
        level=getattr(logging, level),
        format=log_format,
        datefmt=date_format
    )

    logging.getLogger("paramiko").setLevel(logging.WARNING)


def log_event(event_msg: str) -> None:
    if not event_msg:
        return

    max_length = 1000
    sanitized_msg = str(event_msg).replace('\r', ' ').replace('\n', ' ')[:max_length]

    logging.info(sanitized_msg)


def fetch_data_from_remote(
        host: str,
        port: int,
        username: str,
        key_path: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 10
) -> Optional[str]:
    if not host or not isinstance(host, str):
        logging.error("Invalid host specified")
        return None

    if not isinstance(port, int) or port <= 0 or port > 65535:
        logging.error(f"Invalid port number: {port}")
        return None

    if not username or not isinstance(username, str):
        logging.error("Invalid username specified")
        return None

    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        known_hosts_path = os.environ.get("SSH_KNOWN_HOSTS", "~/.ssh/known_hosts")
        known_hosts_path = os.path.expanduser(known_hosts_path)
        if os.path.exists(known_hosts_path):
            client.load_host_keys(known_hosts_path)

        if key_path:
            try:
                client.connect(
                    hostname=host,
                    port=port,
                    username=username,
                    key_filename=key_path,
                    timeout=timeout,
                    allow_agent=False,
                    look_for_keys=False
                )
                log_event(f"Connected to {host}:{port} using key authentication")
            except paramiko.SSHException:
                if password:
                    client.connect(
                        hostname=host,
                        port=port,
                        username=username,
                        password=password,
                        timeout=timeout,
                        allow_agent=False,
                        look_for_keys=False
                    )
                    log_event(f"Connected to {host}:{port} using password authentication")
                else:
                    raise
        elif password:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False
            )
            log_event(f"Connected to {host}:{port} using password authentication")
        else:
            logging.error("No authentication method provided (key or password)")
            return None

        command = "cat /tmp/data.txt"
        stdin, stdout, stderr = client.exec_command(command, timeout=30)

        # Check for errors
        error = stderr.read().decode('utf-8').strip()
        if error:
            logging.error(f"Error executing remote command: {error}")
            client.close()
            return None

        data = stdout.read(1024 * 1024)
        if stdout.readable():
            logging.warning("Data from remote host was truncated (exceeded 1MB)")

        client.close()

        log_event(f"Successfully fetched data from {host}:{port}")
        return data.decode('utf-8', errors='replace')
    except paramiko.SSHException as e:
        logging.error(f"SSH connection failed: {e}")
        return None
    except Exception as e:
        logging.error(f"Connection failed: {str(e)}")
        return None


def save_data_to_file(filepath: str, content: str) -> bool:
    if not filepath or not isinstance(filepath, str):
        logging.error("Invalid filepath specified")
        return False

    if not content:
        logging.warning("No content to save")
        return False

    try:
        abs_path = os.path.abspath(os.path.normpath(filepath))

        safe_dirs = [os.path.abspath(d) for d in [
            os.getcwd(),
            os.environ.get("DATA_DIR", "./data")
        ]]

        is_safe = False
        for safe_dir in safe_dirs:
            if abs_path.startswith(safe_dir):
                is_safe = True
                break

        if not is_safe:
            logging.error(f"Attempted to write to unauthorized location: {abs_path}")
            return False

        os.makedirs(os.path.dirname(abs_path) or '.', exist_ok=True)

        with open(abs_path, 'w', encoding="utf-8") as f:
            f.write(content)

        os.chmod(abs_path, stat.S_IRUSR | stat.S_IWUSR)

        log_event(f"Saved data to {filepath}")
        return True
    except (OSError, IOError) as e:
        logging.error(f"Failed to save data: {e}")
        return False


def main() -> None:
    try:
        config = get_configuration()

        configure_logging(config["logging_level"])

        processor = DataProcessor(config["processing_factor"])
        try:
            sample_data = [1, 2, 3, 4]
            processed_data = processor.process(sample_data)
            log_event(f"Processed data: {processed_data}")
        except Exception as e:
            logging.error(f"Data processing failed: {e}")

        ssh_host = os.environ.get("SSH_HOST", "")
        if not ssh_host:
            logging.warning("No SSH_HOST specified, skipping remote data fetch")
            return

        try:
            ssh_port = int(os.environ.get("SSH_PORT", "22"))
            if ssh_port <= 0 or ssh_port > 65535:
                logging.error(f"Invalid SSH_PORT: {ssh_port}")
                return
        except ValueError:
            logging.error(f"Invalid SSH_PORT: {os.environ.get('SSH_PORT')}")
            return

        ssh_username = os.environ.get("SSH_USERNAME", "")
        if not ssh_username:
            logging.warning("No SSH_USERNAME specified, skipping remote data fetch")
            return

        ssh_key_path = os.environ.get("SSH_KEY_PATH", "")
        if ssh_key_path:
            ssh_key_path = os.path.expanduser(ssh_key_path)
            if not os.path.exists(ssh_key_path):
                logging.warning(f"SSH key not found at {ssh_key_path}")
                ssh_key_path = None

        ssh_password = os.environ.get("SSH_PASSWORD", "")

        if not ssh_key_path and not ssh_password:
            logging.error("No authentication method provided for SSH (key or password)")
            return

        remote_data = fetch_data_from_remote(
            ssh_host, ssh_port, ssh_username, ssh_key_path, ssh_password
        )

        if remote_data:
            data_dir = os.environ.get("DATA_DIR", "./data")
            os.makedirs(data_dir, exist_ok=True)

            random_suffix = secrets.token_hex(8)
            filepath = os.path.join(data_dir, f"fetched_data_{random_suffix}.txt")

            save_data_to_file(filepath, remote_data)
        else:
            logging.warning("No remote data fetched")

    except Exception as e:
        logging.error(f"Application error: {e}")


if __name__ == "__main__":
    main()