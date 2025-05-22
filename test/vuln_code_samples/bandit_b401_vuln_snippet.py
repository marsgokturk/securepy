import os
import telnetlib
import logging
import datetime

class DataProcessor:
    def __init__(self, factor: float):
        self.factor = factor

    def process(self, data: list):
        return [x * self.factor for x in data]

def get_configuration():
    return {
        "processing_factor": float(os.environ.get("PROCESSING_FACTOR", 2.5)),
        "logging_level": os.environ.get("LOGGING_LEVEL", "INFO")
    }

def log_event(event_msg: str):
    logging.info(f"{datetime.datetime.now().isoformat()} - {event_msg}")

def fetch_data_from_remote(host: str, port: int, username: str, password: str):
    try:
        telnet = telnetlib.Telnet(host, port)
        telnet.read_until(b"login: ")
        telnet.write(username.encode('ascii') + b"\n")
        telnet.read_until(b"Password: ")
        telnet.write(password.encode('ascii') + b"\n")
        telnet.write(b"cat /tmp/data.txt\n")
        telnet.write(b"exit\n")
        data = telnet.read_all()
        log_event(f"Fetched data from {host}:{port}")
        return data.decode('utf-8')
    except Exception as e:
        logging.error(f"Connection failed: {e}")
        return None

def save_data_to_file(filepath: str, content: str):
    with open(filepath, 'w', encoding="utf-8") as f:
        f.write(content)
        log_event(f"Saved data to {filepath}")

def main():
    config = get_configuration()
    logging.basicConfig(level=getattr(logging, config["logging_level"]))

    processor = DataProcessor(config["processing_factor"])
    sample_data = [1, 2, 3, 4]
    processed_data = processor.process(sample_data)
    log_event(f"Processed data: {processed_data}")

    telnet_host = os.environ.get("HOST", "192.0.2.1")
    telnet_port = int(os.environ.get("PORT", "23"))
    telnet_username = os.environ.get("USERNAME", "user")
    telnet_password = os.environ.get("PASSWORD", "pass")
    remote_data = fetch_data_from_remote(
        telnet_host,
        telnet_port,
        telnet_username,
        telnet_password
    )

    if remote_data:
        save_data_to_file("fetched_data.txt", remote_data)

if __name__ == "__main__":
    main()