# Secure Folder Encryption Tool

A robust folder encryption/decryption tool featuring AES encryption with secure file deletion capabilities following **DoD 5220.22-M standards**.

![Security Shield](https://img.icons8.com/color/96/000000/security-checked--v1.png) 

## Features

- 🔐 AES-256 encryption in CBC mode
- 🔄 PBKDF2 key derivation with SHA-256
- 🗑️ Secure deletion with 7-pass DoD 5220.22-M compliant overwriting
- 📊 Progress tracking with tqdm
- 🔑 Salt and IV based encryption

## Requirements

- Python 3.8+
- cryptography
- tqdm
- psutil

## Installation

1. Clone this repository:

```bash
git clone <repository-url>
cd <repository-name>
```
2. Install required packages:

```bash
pip install cryptography tqdm psutil
```

## Usage:
The tool can be used to encrypt or decrypt folders using the following commands:

Encryption
```bash
python simple_encrypt.py encrypt <folder_path> --password <your_password>
```
Note: If password is not provided, you will be prompted to enter it

Decryption
```bash
python simple_encrypt.py decrypt <folder_path> --password <your_password> --salt <salt_value> --iv <iv_value>
```

If any of the required values are not provided, you will be prompted to enter them.

## Important Notes
- Store the salt and IV values securely - they are required for decryption
- Original files are securely wiped after encryption
- The encryption process is irreversible without the correct password, salt, and IV
- Encrypted files will have a .enc extension

## Security Features

- Military-grade AES-256 encryption
- 7-pass secure deletion following DoD 5220.22-M standard + one random wipe pass
- Password-based key derivation with 100,000 iterations
- Secure random number generation for cryptographic operations

## Warning
- Always backup important data before encryption
- Store password, salt, and IV values securely
- Lost credentials CANNOT be recovered

## Best Practices

1. Always test with dummy data first
2. Store keys in password managers (Bitwarden/1Password)
3. For SSDs: Encrypt before writing sensitive data
4. Disable cloud sync during operations
5. Verify backups before deletion
