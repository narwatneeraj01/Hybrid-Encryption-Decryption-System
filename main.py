from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import io
import zipfile
from datetime import datetime
import secrets
import logging
from werkzeug.utils import secure_filename

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
UPLOAD_FOLDER = 'temp_uploads'
DOWNLOAD_FOLDER = 'temp_downloads'

# Create directories if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

class HybridCrypto:
    @staticmethod
    def generate_rsa_keys(key_size=2048):
        """Generate RSA key pair"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
            # Serialize keys
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return {
                'private_key': private_pem.decode('utf-8'),
                'public_key': public_pem.decode('utf-8')
            }
        except Exception as e:
            logger.error(f"RSA key generation error: {str(e)}")
            raise

    @staticmethod
    def generate_des_key():
        """Generate 64-bit DES key"""
        return secrets.token_bytes(8)

    @staticmethod
    def pad_data(data, block_size=8):
        """PKCS7 padding for DES"""
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def unpad_data(data):
        """Remove PKCS7 padding"""
        pad_len = data[-1]
        return data[:-pad_len]

    @staticmethod
    def des_encrypt(plaintext, key):
        """Encrypt data using DES in CBC mode"""
        try:
            # Generate random IV
            iv = secrets.token_bytes(8)
            
            # Pad the plaintext
            padded_data = HybridCrypto.pad_data(plaintext.encode('utf-8'))
            
            # Create cipher
            cipher = Cipher(
                algorithms.TripleDES(key + key + key[:8]),  # Convert to 3DES for better security
                modes.CBC(iv),
                backend=default_backend()
            )
            
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Return IV + ciphertext
            return iv + ciphertext
        except Exception as e:
            logger.error(f"DES encryption error: {str(e)}")
            raise

    @staticmethod
    def des_decrypt(ciphertext, key):
        """Decrypt data using DES in CBC mode"""
        try:
            # Extract IV and ciphertext
            iv = ciphertext[:8]
            encrypted_data = ciphertext[8:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.TripleDES(key + key + key[:8]),  # Convert to 3DES
                modes.CBC(iv),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            plaintext = HybridCrypto.unpad_data(padded_plaintext)
            return plaintext.decode('utf-8')
        except Exception as e:
            logger.error(f"DES decryption error: {str(e)}")
            raise

    @staticmethod
    def rsa_encrypt(data, public_key_pem):
        """Encrypt data using RSA public key"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            encrypted = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return encrypted
        except Exception as e:
            logger.error(f"RSA encryption error: {str(e)}")
            raise

    @staticmethod
    def rsa_decrypt(encrypted_data, private_key_pem):
        """Decrypt data using RSA private key"""
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            
            decrypted = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted
        except Exception as e:
            logger.error(f"RSA decryption error: {str(e)}")
            raise

# API Routes
@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    """Generate RSA key pair"""
    try:
        data = request.get_json()
        key_size = data.get('key_size', 2048)
        
        if key_size not in [1024, 2048, 4096]:
            return jsonify({'error': 'Invalid key size. Use 1024, 2048, or 4096'}), 400
        
        keys = HybridCrypto.generate_rsa_keys(key_size)
        
        return jsonify({
            'success': True,
            'keys': keys,
            'key_size': key_size,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Key generation failed: {str(e)}")
        return jsonify({'error': f'Key generation failed: {str(e)}'}), 500

@app.route('/api/encrypt', methods=['POST'])
def encrypt_data():
    """Encrypt data using hybrid encryption"""
    try:
        data = request.get_json()
        plaintext = data.get('plaintext')
        public_key = data.get('public_key')
        
        if not plaintext or not public_key:
            return jsonify({'error': 'Missing plaintext or public key'}), 400
        
        # Step 1: Generate DES key
        des_key = HybridCrypto.generate_des_key()
        
        # Step 2: Encrypt plaintext with DES
        encrypted_data = HybridCrypto.des_encrypt(plaintext, des_key)
        
        # Step 3: Encrypt DES key with RSA
        encrypted_des_key = HybridCrypto.rsa_encrypt(des_key, public_key)
        
        # Convert to base64 for JSON transmission
        encrypted_data_b64 = base64.b64encode(encrypted_data).decode('utf-8')
        encrypted_key_b64 = base64.b64encode(encrypted_des_key).decode('utf-8')
        
        return jsonify({
            'success': True,
            'encrypted_data': encrypted_data_b64,
            'encrypted_key': encrypted_key_b64,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt_data():
    """Decrypt data using hybrid decryption"""
    try:
        data = request.get_json()
        encrypted_data_b64 = data.get('encrypted_data')
        encrypted_key_b64 = data.get('encrypted_key')
        private_key = data.get('private_key')
        
        if not all([encrypted_data_b64, encrypted_key_b64, private_key]):
            return jsonify({'error': 'Missing required decryption parameters'}), 400
        
        # Convert from base64
        encrypted_data = base64.b64decode(encrypted_data_b64)
        encrypted_des_key = base64.b64decode(encrypted_key_b64)
        
        # Step 1: Decrypt DES key with RSA
        des_key = HybridCrypto.rsa_decrypt(encrypted_des_key, private_key)
        
        # Step 2: Decrypt data with DES
        decrypted_text = HybridCrypto.des_decrypt(encrypted_data, des_key)
        
        return jsonify({
            'success': True,
            'decrypted_data': decrypted_text,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

@app.route('/api/encrypt-file', methods=['POST'])
def encrypt_file():
    """Encrypt uploaded file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        public_key = request.form.get('public_key')
        
        if file.filename == '' or not public_key:
            return jsonify({'error': 'Missing file or public key'}), 400
        
        # Read file content
        file_content = file.read().decode('utf-8')
        
        # Generate DES key
        des_key = HybridCrypto.generate_des_key()
        
        # Encrypt file content with DES
        encrypted_data = HybridCrypto.des_encrypt(file_content, des_key)
        
        # Encrypt DES key with RSA
        encrypted_des_key = HybridCrypto.rsa_encrypt(des_key, public_key)
        
        # Create zip file with encrypted data and key
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr('encrypted_data.bin', encrypted_data)
            zip_file.writestr('encrypted_key.bin', encrypted_des_key)
            zip_file.writestr('original_filename.txt', secure_filename(file.filename))
        
        zip_buffer.seek(0)
        
        return send_file(
            io.BytesIO(zip_buffer.read()),
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'encrypted_{secure_filename(file.filename)}.zip'
        )
    
    except Exception as e:
        logger.error(f"File encryption failed: {str(e)}")
        return jsonify({'error': f'File encryption failed: {str(e)}'}), 500

@app.route('/api/decrypt-file', methods=['POST'])
def decrypt_file():
    """Decrypt uploaded encrypted file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        private_key = request.form.get('private_key')
        
        if file.filename == '' or not private_key:
            return jsonify({'error': 'Missing file or private key'}), 400
        
        # Read zip file
        zip_file = zipfile.ZipFile(io.BytesIO(file.read()))
        
        # Extract encrypted data and key
        encrypted_data = zip_file.read('encrypted_data.bin')
        encrypted_des_key = zip_file.read('encrypted_key.bin')
        
        try:
            original_filename = zip_file.read('original_filename.txt').decode('utf-8')
        except:
            original_filename = 'decrypted_file.txt'
        
        # Decrypt DES key with RSA
        des_key = HybridCrypto.rsa_decrypt(encrypted_des_key, private_key)
        
        # Decrypt data with DES
        decrypted_content = HybridCrypto.des_decrypt(encrypted_data, des_key)
        
        return send_file(
            io.BytesIO(decrypted_content.encode('utf-8')),
            mimetype='text/plain',
            as_attachment=True,
            download_name=f'decrypted_{original_filename}'
        )
    
    except Exception as e:
        logger.error(f"File decryption failed: {str(e)}")
        return jsonify({'error': f'File decryption failed: {str(e)}'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/info', methods=['GET'])
def system_info():
    """Get system information"""
    return jsonify({
        'system': 'Hybrid Encryption-Decryption System',
        'algorithms': {
            'symmetric': 'Triple DES (3DES)',
            'asymmetric': 'RSA with OAEP padding',
            'hash': 'SHA-256'
        },
        'supported_key_sizes': [1024, 2048, 4096],
        'max_file_size': '16MB',
        'developer': 'Neeraj Narwat',
        'timestamp': datetime.now().isoformat()
    })

# Error handlers
@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 16MB.'}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    print("🔐 Hybrid Encryption-Decryption Server")
    print("📍 Server starting on http://localhost:5000")
    print("🔑 Endpoints available:")
    print("   POST /api/generate-keys - Generate RSA key pair")
    print("   POST /api/encrypt - Encrypt text data")
    print("   POST /api/decrypt - Decrypt text data")
    print("   POST /api/encrypt-file - Encrypt file")
    print("   POST /api/decrypt-file - Decrypt file")
    print("   GET  /api/health - Health check")
    print("   GET  /api/info - System information")
    print("=" * 50)
    
    app.run(debug=True, host='0.0.0.0', port=5000)