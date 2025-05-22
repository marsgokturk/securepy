import os
import logging
import tempfile
from typing import List
import paramiko


class DataExtractor:
    def extract_data(self) -> List[str]:
        return [f"record_{i}" for i in range(10)]


class ArchiveManager:
    def create_archive(self, records: List[str], destination: str) -> str:
        archive_path = os.path.join(destination, "data_archive.txt")
        with open(archive_path, 'w') as f:
            for record in records:
                f.write(f"{record}\n")
        return archive_path


def process_records(records: List[str]) -> List[str]:
    return [r.upper() for r in records]


def log_upload_result(filename: str, success: bool):
    if success:
        logging.info(f"Upload of {filename} completed successfully.")
    else:
        logging.error(f"Upload of {filename} failed.")


def upload_file_via_sftp(filepath: str, remote_filename: str):
    sftp_host = os.environ.get('SFTP_HOST')
    sftp_user = os.environ.get('SFTP_USER')
    sftp_pass = os.environ.get('SFTP_PASS')

    if not all([sftp_host, sftp_user, sftp_pass]):
        raise ValueError("SFTP credentials are not set in the environment variables.")

    host_key = paramiko.AutoAddPolicy()

    transport = paramiko.Transport((sftp_host, 22))
    transport.set_log_channel('paramiko.transport')
    try:
        transport.connect(username=sftp_user, password=sftp_pass, hostkey=host_key)

        with paramiko.SFTPClient.from_transport(transport) as sftp:
            sftp.put(filepath, remote_filename)
            log_upload_result(remote_filename, True)
    except Exception as e:
        log_upload_result(remote_filename, False)
        logging.exception("Error uploading via SFTP: %s", e)
    finally:
        transport.close()


def export_and_transfer_data():
    extractor = DataExtractor()
    records = extractor.extract_data()
    processed = process_records(records)
    with tempfile.TemporaryDirectory() as tempdir:
        archive_mgr = ArchiveManager()
        archive_file = archive_mgr.create_archive(processed, tempdir)
        filename = os.path.basename(archive_file)
        upload_file_via_sftp(archive_file, filename)


def cleanup_archives(path: str):
    if os.path.exists(path):
        os.remove(path)
        logging.info(f"Removed archive at {path}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    export_and_transfer_data()