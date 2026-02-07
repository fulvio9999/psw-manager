from __future__ import annotations

import base64
import os
import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_salt() -> str:
    return secrets.token_hex(16)


def derive_key(password: str, salt_hex: str) -> bytes:
    iterations = int(os.getenv("KDF_ITERATIONS", "200000"))
    salt = bytes.fromhex(salt_hex)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return key


def encrypt(key: bytes, plaintext: str) -> str:
    token = Fernet(key).encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt(key: bytes, token: str) -> str:
    plaintext = Fernet(key).decrypt(token.encode("utf-8"))
    return plaintext.decode("utf-8")
