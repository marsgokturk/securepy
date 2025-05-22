import paramiko
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SSHClientManager:
    def __init__(self, hostname, port, username, password):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.client = None

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            hostname=self.hostname,
            port=self.port,
            username=self.username,
            password=self.password,
            look_for_keys=False,
            allow_agent=False
        )
        logger.info(f"Connected to {self.hostname}")

    def disconnect(self):
        if self.client:
            self.client.close()
            logger.info(f"Disconnected from {self.hostname}")

    def run_command(self, command):
        if not self.client:
            raise Exception("Not connected")
        stdin, stdout, stderr = self.client.exec_command(command)
        out = stdout.read().decode()
        err = stderr.read().decode()
        logger.info(f"Executed command: {command}")
        if out:
            logger.info(f"STDOUT: {out}")
        if err:
            logger.warning(f"STDERR: {err}")
        return out, err

    def upload_file(self, local_path, remote_path):
        if not self.client:
            raise Exception("Not connected")
        sftp = self.client.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()
        logger.info(f"Uploaded {local_path} to {remote_path}")

    def download_file(self, remote_path, local_path):
        if not self.client:
            raise Exception("Not connected")
        sftp = self.client.open_sftp()
        sftp.get(remote_path, local_path)
        sftp.close()
        logger.info(f"Downloaded {remote_path} to {local_path}")

    def list_directory(self, remote_path):
        if not self.client:
            raise Exception("Not connected")
        sftp = self.client.open_sftp()
        files = sftp.listdir(remote_path)
        sftp.close()
        logger.info(f"Listed directory {remote_path}: {files}")
        return files


def calculate_checksum(file_path):
    import hashlib
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def convert_bytes_to_human_readable(num_bytes):
    for unit in ['B','KB','MB','GB','TB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"

