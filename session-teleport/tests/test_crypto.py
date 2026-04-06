"""Tests for encryption/decryption."""

import pytest

from session_teleport.core.crypto import decrypt_bundle, encrypt_bundle


def test_encrypt_decrypt_roundtrip():
    data = b"Hello, this is session data!"
    passphrase = "test-password-123"

    encrypted = encrypt_bundle(data, passphrase)
    assert encrypted != data

    decrypted = decrypt_bundle(encrypted, passphrase)
    assert decrypted == data


def test_wrong_passphrase():
    data = b"secret stuff"
    encrypted = encrypt_bundle(data, "correct-pass")

    with pytest.raises(ValueError, match="wrong passphrase"):
        decrypt_bundle(encrypted, "wrong-pass")


def test_different_encryptions_differ():
    data = b"same data"
    enc1 = encrypt_bundle(data, "pass")
    enc2 = encrypt_bundle(data, "pass")
    # Different random salts should produce different ciphertext
    assert enc1 != enc2
