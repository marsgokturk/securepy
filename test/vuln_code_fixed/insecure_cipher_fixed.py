import base64
import hashlib
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class DataProcessor:
    def __init__(self, password: bytes, salt: bytes = None):
        self.salt = salt or get_random_bytes(16)
        self.key = PBKDF2(password, self.salt, dkLen=32, count=100_000, hmac_hash_module=hashlib.sha256)

    def encrypt_sensitive_data(self, plaintext: str) -> str:
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        data = cipher.nonce + tag + ciphertext
        return base64.b64encode(self.salt + data).decode('utf-8')

    def decrypt_sensitive_data(self, ciphertext_b64: str) -> str:
        raw = base64.b64decode(ciphertext_b64)
        salt = raw[:16]
        self.key = PBKDF2(self.key, salt, dkLen=32, count=100_000, hmac_hash_module=hashlib.sha256)
        nonce = raw[16:16 + 16]
        tag = raw[32:32 + 16]
        ciphertext = raw[48:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

    def hash_document(self, document: str) -> str:
        return hashlib.sha256(document.encode('utf-8')).hexdigest()

    def generate_user_token(self, username: str, secret: str) -> str:
        user_salt = hashlib.sha256(username.encode()).digest()
        token = hashlib.pbkdf2_hmac('sha256', secret.encode('utf-8'), user_salt, 100_000)
        return base64.urlsafe_b64encode(token).decode('utf-8').rstrip("=")


def process_documents(documents, password):
    processor = DataProcessor(password)
    results = {}
    for doc_name, doc_data in documents.items():
        signature = processor.hash_document(doc_data)
        enc = processor.encrypt_sensitive_data(doc_data)
        token = processor.generate_user_token(doc_name, password)
        results[doc_name] = {
            'hash': signature,
            'encrypted': enc,
            'token': token,
        }
    return results