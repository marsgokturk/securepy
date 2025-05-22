import os
from ftplib import FTP
import logging
import tempfile
from typing import List

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

def upload_file_via_ftp(filepath: str, remote_filename: str):

    ftp_host = os.environ.get('HOST')
    ftp_user = os.environ.get('USER')
    ftp_pass = os.environ.get('PASS')

    if not all([ftp_host, ftp_user, ftp_pass]):
        raise ValueError("Credentials are not set in the environment variables.")

    ftp = FTP()
    ftp.connect(ftp_host, 21)
    ftp.login(ftp_user, ftp_pass)

    try:
        with open(filepath, 'rb') as f:
            ftp.storbinary(f'STOR {remote_filename}', f)
        log_upload_result(remote_filename, True)
    except Exception as e:
        log_upload_result(remote_filename, False)
        logging.exception("Error uploading via FTP: %s", e)
    finally:
        ftp.quit()


def export_and_transfer_data():
    extractor = DataExtractor()
    records = extractor.extract_data()
    processed = process_records(records)

    with tempfile.TemporaryDirectory() as tempdir:
        archive_mgr = ArchiveManager()
        archive_file = archive_mgr.create_archive(processed, tempdir)
        filename = os.path.basename(archive_file)

        upload_file_via_ftp(archive_file, filename)

def cleanup_archives(path: str):
    if os.path.exists(path):
        os.remove(path)
        logging.info(f"Removed archive at {path}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    export_and_transfer_data()