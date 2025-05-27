# 🔐 Hybrid Encryption-Decryption System

A web-based application combining **3DES** and **RSA** algorithms for secure data encryption.

![image](https://github.com/user-attachments/assets/48fd4f12-2d04-48b7-b2a1-57d386a851ad)


## Features

- **Hybrid Encryption**: 3DES + RSA for optimal security
- **Web Interface**: Modern, responsive UI
- **File Support**: Encrypt/decrypt text files
- **Key Generation**: RSA key pairs (1024/2048/4096-bit)
- **Real-time Status**: Live progress updates

## Quick Start

### Installation
```bash
git clone https://github.com/yourusername/hybrid-encryption-system.git
cd hybrid-encryption-system
pip install -r requirements.txt
python app.py
```

### Usage
1. Open `http://localhost:5000`
2. Click "Generate RSA Keys"
3. Enter text or upload file
4. Click "Encrypt Data"
5. Copy encrypted output

## Requirements

```
Flask==2.3.3
Flask-CORS==4.0.0
cryptography==41.0.7
```

## API Endpoints

- `POST /api/generate-keys` - Generate RSA keys
- `POST /api/encrypt` - Encrypt data
- `POST /api/decrypt` - Decrypt data
- `GET /api/health` - Health check

## How It Works

1. **Encryption**: Data encrypted with 3DES, key encrypted with RSA
2. **Decryption**: RSA decrypts key, then 3DES decrypts data
3. **Security**: OAEP padding, secure random generation

## Project Structure

```
├── app.py          # Flask backend
├── index.html      # Web interface
├── requirements.txt
├── temp_uploads/
└── temp_downloads/
```

## Security Features

- **3DES**: 168-bit symmetric encryption
- **RSA**: OAEP padding with SHA-256
- **Random Keys**: Cryptographically secure generation
- **File Size Limit**: 16MB maximum

## Developer

**Neeraj Narwat**  
Department of Computer Science & Engineering

## License

MIT License - see [LICENSE](LICENSE) file for details.
