"""Encryption and decryption for session bundles using Fernet (AES-128-CBC + HMAC)."""

import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_LENGTH = 16
ITERATIONS = 480_000


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def encrypt_bundle(data: bytes, passphrase: str) -> bytes:
    """Encrypt bundle data with a passphrase. Returns salt + ciphertext."""
    salt = os.urandom(SALT_LENGTH)
    key = _derive_key(passphrase, salt)
    f = Fernet(key)
    ciphertext = f.encrypt(data)
    return salt + ciphertext


def decrypt_bundle(encrypted: bytes, passphrase: str) -> bytes:
    """Decrypt bundle data with a passphrase. Expects salt + ciphertext."""
    salt = encrypted[:SALT_LENGTH]
    ciphertext = encrypted[SALT_LENGTH:]
    key = _derive_key(passphrase, salt)
    f = Fernet(key)
    try:
        return f.decrypt(ciphertext)
    except InvalidToken:
        raise ValueError("Decryption failed: wrong passphrase or corrupted bundle")
