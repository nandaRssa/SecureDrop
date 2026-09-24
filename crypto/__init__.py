"""
Modul Core Encryption (Orang 1 — Core Encryption).
Menyediakan antarmuka derivasi kunci (KDF) dan algoritma cipher AES-256-GCM.
"""

from .kdf import (
    generate_salt,
    derive_key,
    SALT_LENGTH,
    KEY_LENGTH,
    PBKDF2_ITERATIONS,
)
from .aes_gcm import (
    generate_nonce,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    AESGCMResult,
    AES_KEY_LENGTH,
    AES_NONCE_LENGTH,
    AES_TAG_LENGTH,
)

__all__ = [
    "generate_salt",
    "derive_key",
    "SALT_LENGTH",
    "KEY_LENGTH",
    "PBKDF2_ITERATIONS",
    "generate_nonce",
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
    "AESGCMResult",
    "AES_KEY_LENGTH",
    "AES_NONCE_LENGTH",
    "AES_TAG_LENGTH",
]
