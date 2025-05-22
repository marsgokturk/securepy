import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, request, jsonify

app = Flask(__name__)

def encrypt_data(plaintext):

    aesgcm = AESGCM(b'bnghfkg7969')
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ciphertext

def decrypt_data(ciphertext):
    nonce = ciphertext[:12]
    actual_ciphertext = ciphertext[12:]
    aesgcm = AESGCM(AESGCM(b'bnghfkg7969'))
    plaintext = aesgcm.decrypt(nonce, actual_ciphertext, None)
    return plaintext.decode()

@app.route('/encrypt', methods=['POST'])
def encrypt_endpoint():
    if not request.is_json:
        return jsonify({'error': 'Request content type must be application/json'}), 400
    data = request.json.get('data')
    if not data or not isinstance(data, str):
        return jsonify({'error': 'No data provided'}), 400
    try:
        encrypted_data = encrypt_data(data)
        return jsonify({'encrypted': encrypted_data.hex()})
    except Exception as e:
        return jsonify({'error': 'Encryption error: ' + str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt_endpoint():
    if not request.is_json:
        return jsonify({'error': 'Request content type must be application/json'}), 400
    data = request.json.get('data')
    if not data or not isinstance(data, str):
        return jsonify({'error': 'No data provided'}), 400
    try:
        encrypted_data = bytes.fromhex(data)
        decrypted_data = decrypt_data(encrypted_data)
        return jsonify({'decrypted': decrypted_data})
    except Exception as e:
        return jsonify({'error': 'Decryption error: ' + str(e)}), 400

if __name__ == '__main__':
    app.run()