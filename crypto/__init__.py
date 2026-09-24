"""
Modul Core Encryption (Orang 1 — Core Encryption).
Menyediakan antarmuka derivasi kunci (KDF) dan algoritma cipher modern.
"""

from .kdf import (
    generate_salt,
    derive_key,
    SALT_LENGTH,
    KEY_LENGTH,
    PBKDF2_ITERATIONS,
)

__all__ = [
    "generate_salt",
    "derive_key",
    "SALT_LENGTH",
    "KEY_LENGTH",
    "PBKDF2_ITERATIONS",
]
