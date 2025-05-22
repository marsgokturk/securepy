import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class EncryptionService:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.initialize_keys()

    def initialize_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024
        )
        self.public_key = self.private_key.public_key()

    def get_public_key_pem(self):
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_pem.decode('utf-8')

    def encrypt_message(self, message):
        ciphertext = self.public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt_message(self, encrypted_message):
        ciphertext = base64.b64decode(encrypted_message)
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')