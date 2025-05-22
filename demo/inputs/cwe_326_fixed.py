import os
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def generate_strong_rsa_keypair(bits=3072):
    key = RSA.generate(bits)
    return key

def encrypt_with_aes256(data: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes.")
    cipher = AES.new(key, AES.MODE_GCM)
    iv = cipher.nonce
    ct, tag = cipher.encrypt_and_digest(data)
    return iv + tag + ct

def decrypt_with_aes256(ciphertext: bytes, key: bytes) -> bytes:
    iv = ciphertext[:16]
    tag = ciphertext[16:32]
    ct = ciphertext[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    data = cipher.decrypt_and_verify(ct, tag)
    return data

def hash_file(filepath: str) -> str:
    import hashlib
    with open(filepath, "rb") as f:
        hasher = hashlib.sha256()
        while True:
            buf = f.read(8192)
            if not buf:
                break
            hasher.update(buf)
    logger.info("File hashed with SHA-256.")
    return hasher.hexdigest()
