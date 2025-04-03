from flask import Flask, request, jsonify, render_template
import base64, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

server = Flask(__name__)

# --- Asymmetric Demo RSA Key Pair (server-generated) ---
rsa_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
rsa_public_key = rsa_private_key.public_key()

@server.route('/')
def index():
    return render_template('index.html')

@server.route('/decrypt/symmetric', methods=['POST'])
def decrypt_symmetric():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        key = base64.b64decode(data['key'])
        iv = base64.b64decode(data['iv'])
        ciphertext = base64.b64decode(data['ciphertext'])
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None).decode('utf-8')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'plaintext': plaintext})

@server.route('/public-key', methods=['GET'])
def public_key():
    try:
        pem = rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print("Server RSA Public Key:\n" + pem.decode('utf-8'))
        pem_b64 = base64.b64encode(pem).decode('utf-8')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'public_key': pem_b64})

@server.route('/decrypt/asymmetric', methods=['POST'])
def decrypt_asymmetric():
    data = request.get_json()
    if not data or 'ciphertext' not in data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        ciphertext = base64.b64decode(data['ciphertext'])
        plaintext_bytes = rsa_private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        plaintext = plaintext_bytes.decode('utf-8')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'plaintext': plaintext})

# --- Hybrid Demo Variables & Endpoints ---
hybrid_symmetric_key = None  # will hold the AES-GCM key generated during key exchange

@server.route('/exchange-key', methods=['POST'])
def exchange_key():
    global hybrid_symmetric_key
    data = request.get_json()
    if not data or 'client_public_key' not in data:
        return jsonify({'error': 'No client public key provided'}), 400

    try:
        # Expecting a base64-encoded PEM string from client
        client_pubkey_pem = base64.b64decode(data['client_public_key'])
        client_public_key = serialization.load_pem_public_key(client_pubkey_pem)

        # Generate a new symmetric key (32 bytes for AES-256)
        hybrid_symmetric_key = os.urandom(32)

        # Encrypt the symmetric key with the client's public key using RSA-OAEP
        encrypted_sym_key = client_public_key.encrypt(
            hybrid_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_sym_key_b64 = base64.b64encode(encrypted_sym_key).decode('utf-8')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'encrypted_symmetric_key': encrypted_sym_key_b64})

@server.route('/decrypt/hybrid', methods=['POST'])
def decrypt_hybrid():
    global hybrid_symmetric_key
    data = request.get_json()
    if not data or 'ciphertext' not in data or 'iv' not in data:
        return jsonify({'error': 'Missing data'}), 400

    try:
        ciphertext = base64.b64decode(data['ciphertext'])
        iv = base64.b64decode(data['iv'])
        aesgcm = AESGCM(hybrid_symmetric_key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None).decode('utf-8')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'plaintext': plaintext})

if __name__ == '__main__':
    server.run(debug=True)
