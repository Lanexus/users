#!/usr/bin/env python3
"""
DeepValidator V27 - Loader
Decrypts and runs the encrypted main script
"""
import os, sys, base64, tempfile, subprocess
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VERSION = "V27.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENCRYPTED_FILE = os.path.join(SCRIPT_DIR, "encrypted.bin")

def decrypt_and_run(password):
    """Decrypt and execute the main script"""
    if not os.path.exists(ENCRYPTED_FILE):
        print(f"\033[91m[!] encrypted.bin not found\033[0m")
        sys.exit(1)
    
    # Read encrypted file
    with open(ENCRYPTED_FILE, 'rb') as f:
        data = f.read()
    
    salt = data[:16]
    encrypted = data[16:]
    
    # Derive key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    # Decrypt
    try:
        fernet = Fernet(key)
        plaintext = fernet.decrypt(encrypted).decode('utf-8')
    except Exception:
        print(f"\033[91m[!] Invalid password\033[0m")
        sys.exit(1)
    
    # Write to temp file and execute
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
    tmp.write(plaintext)
    tmp.close()
    
    try:
        os.execv(sys.executable, [sys.executable, tmp.name] + sys.argv[1:])
    finally:
        os.unlink(tmp.name)

if __name__ == "__main__":
    import getpass
    print(f"\033[38;5;51mDeepValidator {VERSION}\033[0m")
    password = getpass.getpass("Password: ")
    decrypt_and_run(password)
