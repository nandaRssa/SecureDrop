"""
Modul Core Encryption (Orang 1 — Core Encryption).
Menyediakan antarmuka derivasi kunci (KDF), algoritma cipher AES-256-GCM, dan ChaCha20-Poly1305.
"""

from .kdf import (
    generate_salt,
    derive_key,
    SALT_LENGTH,
    KEY_LENGTH,
    PBKDF2_ITERATIONS,
)
from .aes_gcm import (
    generate_nonce as generate_aes_nonce,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    AESGCMResult,
    AES_KEY_LENGTH,
    AES_NONCE_LENGTH,
    AES_TAG_LENGTH,
)
from .chacha20 import (
    generate_nonce as generate_chacha_nonce,
    encrypt_chacha20,
    decrypt_chacha20,
    ChaCha20Result,
    CHACHA20_KEY_LENGTH,
    CHACHA20_NONCE_LENGTH,
    CHACHA20_TAG_LENGTH,
)

__all__ = [
    "generate_salt",
    "derive_key",
    "SALT_LENGTH",
    "KEY_LENGTH",
    "PBKDF2_ITERATIONS",
    "generate_aes_nonce",
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
    "AESGCMResult",
    "AES_KEY_LENGTH",
    "AES_NONCE_LENGTH",
    "AES_TAG_LENGTH",
    "generate_chacha_nonce",
    "encrypt_chacha20",
    "decrypt_chacha20",
    "ChaCha20Result",
    "CHACHA20_KEY_LENGTH",
    "CHACHA20_NONCE_LENGTH",
    "CHACHA20_TAG_LENGTH",
]

