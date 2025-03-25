"""
Encryption module that supports:
- AES-256-GCM with PBKDF2
- ChaCha20-Poly1305 with Argon2
"""

import os
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# Constants
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

# ================== PBKDF2 Key Derivation ==================
def derive_key_pbkdf2(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=100_000
    )
    return kdf.derive(password.encode())

# ================== Argon2 Key Derivation ==================
def derive_key_argon2(password: str, salt: bytes) -> bytes:
    kdf = Argon2id(
        time_cost=2,
        memory_cost=2**16,
        parallelism=2,
        length=KEY_SIZE,
        salt=salt
    )
    return kdf.derive(password.encode())

# ================== AES-GCM Encryption ==================
def encrypt_aes_gcm(password: str, input_bytes: bytes) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key_pbkdf2(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, input_bytes, None)
    return salt + nonce + ciphertext

# ================== AES-GCM Decryption ==================
def decrypt_aes_gcm(password: str, encrypted_data: bytes) -> bytes:
    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    ciphertext = encrypted_data[SALT_SIZE+NONCE_SIZE:]
    key = derive_key_pbkdf2(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# ================== ChaCha20 Encryption ==================
def encrypt_chacha(password: str, input_bytes: bytes) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key_argon2(password, salt)
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, input_bytes, None)
    return salt + nonce + ciphertext

# ================== ChaCha20 Decryption ==================
def decrypt_chacha(password: str, encrypted_data: bytes) -> bytes:
    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    ciphertext = encrypted_data[SALT_SIZE+NONCE_SIZE:]
    key = derive_key_argon2(password, salt)
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, None)

# ================== File I/O Utilities ==================
def encrypt_file(method: str, input_path: str, output_path: str, password: str):
    with open(input_path, 'rb') as f:
        input_data = f.read()

    if method == 'AES-256-GCM':
        encrypted = encrypt_aes_gcm(password, input_data)
    elif method == 'ChaCha20-Poly1305':
        encrypted = encrypt_chacha(password, input_data)
    else:
        raise ValueError("Invalid encryption method selected.")

    with open(output_path, 'wb') as f:
        f.write(encrypted)

def decrypt_file(method: str, input_path: str, output_path: str, password: str):
    with open(input_path, 'rb') as f:
        encrypted_data = f.read()

    if method == 'AES-256-GCM':
        decrypted = decrypt_aes_gcm(password, encrypted_data)
    elif method == 'ChaCha20-Poly1305':
        decrypted = decrypt_chacha(password, encrypted_data)
    else:
        raise ValueError("Invalid decryption method selected.")

    with open(output_path, 'wb') as f:
        f.write(decrypted)
