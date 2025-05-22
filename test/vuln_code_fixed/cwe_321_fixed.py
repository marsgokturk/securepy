import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, request, jsonify

app = Flask(__name__)

KEY = os.environ.get('APP_SECRET_KEY')
if not KEY:
    raise ValueError("Encryption key not set! Set APP_SECRET_KEY env variable.")
key_bytes = base64.b64decode(KEY)

def encrypt_data(plaintext):
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_data(encoded):
    raw = base64.b64decode(encoded)
    nonce = raw[:12]
    ct = raw[12:]
    aesgcm = AESGCM(key_bytes)
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return plaintext.decode('utf-8')

@app.route('/encrypt', methods=['POST'])
def encrypt_endpoint():
    if not request.is_json or 'data' not in request.json:
        return jsonify({'error': 'No data provided'}), 400
    data = request.json.get('data')
    try:
        encrypted_data = encrypt_data(data)
        return jsonify({'encrypted': encrypted_data})
    except Exception as e:
        return jsonify({'error': 'Encryption error: ' + str(e)}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt_endpoint():
    if not request.is_json or 'data' not in request.json:
        return jsonify({'error': 'No data provided'}), 400
    data = request.json.get('data')
    try:
        decrypted_data = decrypt_data(data)
        return jsonify({'decrypted': decrypted_data})
    except Exception as e:
        return jsonify({'error': 'Decryption error: ' + str(e)}), 400

if __name__ == '__main__':
    app.run()