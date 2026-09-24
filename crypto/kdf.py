"""
SecureDrop - Key Derivation Function (KDF) Module
Mengimplementasikan derivasi kunci berbasis password menggunakan PBKDF2-HMAC-SHA256
sesuai standar keamanan modern (NIST SP 800-132 & OWASP Guidelines).
"""

import secrets
from typing import Union
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ==============================================================================
# KONSTANTA KONFIGURASI KRIPTOGRAFI
# ==============================================================================

# Panjang salt dalam byte (16 byte = 128 bit).
# Standar minimum yang direkomendasikan oleh NIST SP 800-132 untuk mencegah collision.
SALT_LENGTH: int = 16

# Panjang derived key dalam byte (32 byte = 256 bit).
# Disesuaikan tepat untuk ukuran kunci algoritma AES-256-GCM dan ChaCha20-Poly1305.
KEY_LENGTH: int = 32

# Jumlah iterasi PBKDF2.
# Mengikuti rekomendasi OWASP Password Storage (2023) untuk PBKDF2-HMAC-SHA256 (600.000 iterasi)
# untuk memberikan resistensi tinggi terhadap serangan brute-force berbasis GPU/ASIC.
PBKDF2_ITERATIONS: int = 600_000


# ==============================================================================
# FUNGSI GENERASI SALT & DERIVASI KUNCI
# ==============================================================================

def generate_salt(length: int = SALT_LENGTH) -> bytes:
    """
    Menghasilkan cryptographically secure random salt menggunakan CSPRNG (secrets).

    Args:
        length (int): Panjang salt dalam byte (default: 16 byte).

    Returns:
        bytes: Nilai salt acak sepanjang 'length' byte.

    Raises:
        ValueError: Jika panjang salt kurang dari 16 byte.
    """
    if not isinstance(length, int) or length < 16:
        raise ValueError("Panjang salt minimal harus 16 byte.")
    
    return secrets.token_bytes(length)


def derive_key(
    password: Union[str, bytes],
    salt: bytes,
    iterations: int = PBKDF2_ITERATIONS,
    length: int = KEY_LENGTH
) -> bytes:
    """
    Menderivasi cryptographic key berukuran 256-bit (32 byte) dari password dan salt
    menggunakan algoritma PBKDF2-HMAC-SHA256.

    Alur Proses:
        Password (UTF-8 bytes) + Random Salt (16 bytes)
        -> PBKDF2-HMAC-SHA256 (600.000 iterasi)
        -> Derived Key (32 bytes / 256 bit)

    Args:
        password (Union[str, bytes]): Password pengguna. Jika string, akan dikonversi ke UTF-8.
        salt (bytes): Nilai salt acak (harus berupa bytes dengan panjang minimal 16 byte).
        iterations (int): Jumlah iterasi hashing (default: 600.000).
        length (int): Panjang kunci yang dihasilkan dalam byte (default: 32 byte).

    Returns:
        bytes: Kunci turunan 32-byte (256-bit) siap pakai untuk AES-256 / ChaCha20.

    Raises:
        TypeError: Jika tipe data password atau salt tidak valid.
        ValueError: Jika password kosong, salt tidak valid, atau parameter di luar batas aman.
    """
    # Validasi Password
    if password is None:
        raise TypeError("Password tidak boleh bernilai None.")

    if isinstance(password, str):
        if len(password) == 0:
            raise ValueError("Password tidak boleh kosong.")
        password_bytes = password.encode("utf-8")
    elif isinstance(password, bytes):
        if len(password) == 0:
            raise ValueError("Password bytes tidak boleh kosong.")
        password_bytes = password
    else:
        raise TypeError("Password harus berupa string atau bytes.")

    # Validasi Salt
    if not isinstance(salt, bytes):
        raise TypeError("Salt harus bertipe bytes.")

    if len(salt) < 16:
        raise ValueError("Salt harus memiliki panjang minimal 16 byte.")

    # Validasi Iterasi & Panjang Kunci
    if not isinstance(iterations, int) or iterations < 100_000:
        raise ValueError("Jumlah iterasi minimal adalah 100.000.")

    if not isinstance(length, int) or length != 32:
        raise ValueError("Panjang derived key harus tepat 32 byte (256 bit).")

    # Inisialisasi PBKDF2HMAC menggunakan SHA-256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )

    # Eksekusi derivasi kunci
    derived_key = kdf.derive(password_bytes)

    return derived_key
