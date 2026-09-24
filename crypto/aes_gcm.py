"""
SecureDrop - AES-256-GCM Encryption Module
Mengimplementasikan Authenticated Encryption with Associated Data (AEAD) menggunakan AES-256-GCM
sesuai standar NIST SP 800-38D dan memanfaatkan library cryptography teruji.
"""

import secrets
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ==============================================================================
# KONSTANTA KONFIGURASI KRIPTOGRAFI AES-GCM
# ==============================================================================

# Panjang kunci AES-256 dalam byte (32 byte = 256 bit).
AES_KEY_LENGTH: int = 32

# Panjang nonce/IV standar untuk mode GCM (12 byte = 96 bit).
# 96 bit adalah ukuran optimal rekomendasi NIST SP 800-38D yang diproses tanpa hashing tambahan.
AES_NONCE_LENGTH: int = 12

# Panjang authentication tag standar (16 byte = 128 bit).
# Menyediakan integritas dan otentikasi data tingkat tinggi.
AES_TAG_LENGTH: int = 16


# ==============================================================================
# STRUKTUR DATA HASIL ENKRIPSI
# ==============================================================================

@dataclass(frozen=True)
class AESGCMResult:
    """
    Struktur data container untuk memuat komponen hasil enkripsi AES-256-GCM.
    
    Attributes:
        nonce (bytes): Nonce acak 12-byte (96-bit) yang digunakan saat enkripsi.
        ciphertext (bytes): Data terenkripsi (panjang sama persis dengan plaintext).
        tag (bytes): Authentication Tag 16-byte (128-bit) untuk verifikasi integritas.
    """
    nonce: bytes
    ciphertext: bytes
    tag: bytes


# ==============================================================================
# FUNGSI NONCE & ENKRIPSI AES-256-GCM
# ==============================================================================

def generate_nonce(length: int = AES_NONCE_LENGTH) -> bytes:
    """
    Menghasilkan nonce/IV acak menggunakan CSPRNG (secrets).

    Args:
        length (int): Panjang nonce dalam byte (default: 12 byte).

    Returns:
        bytes: Nonce acak berukuran 12 byte.

    Raises:
        ValueError: Jika panjang nonce bukan 12 byte.
    """
    if not isinstance(length, int) or length != AES_NONCE_LENGTH:
        raise ValueError(f"Panjang nonce AES-GCM harus tepat {AES_NONCE_LENGTH} byte (96 bit).")
    
    return secrets.token_bytes(length)


def encrypt_aes_gcm(
    key: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None
) -> AESGCMResult:
    """
    Mengenkskripsi plaintext (binary/bytes) menggunakan algoritma AES-256-GCM.

    Alur:
        Plaintext (bytes) + 32-byte Key + Random 12-byte Nonce
        -> AES-256-GCM
        -> Ciphertext (bytes) + Authentication Tag (16 bytes)

    Args:
        key (bytes): Kunci simetris 256-bit (harus tepat 32 byte dari KDF).
        plaintext (bytes): Data biner yang akan dienkripsi.
        associated_data (Optional[bytes]): Data tambahan terotentikasi (AAD) opsional.

    Returns:
        AESGCMResult: Objek yang memuat nonce (12B), ciphertext, dan tag (16B).

    Raises:
        TypeError: Jika tipe data key atau plaintext bukan bytes.
        ValueError: Jika panjang key tidak tepat 32 byte.
    """
    # Validasi Key
    if not isinstance(key, bytes):
        raise TypeError("Key harus bertipe bytes.")
    if len(key) != AES_KEY_LENGTH:
        raise ValueError(f"Panjang key AES-256 harus tepat {AES_KEY_LENGTH} byte (256 bit).")

    # Validasi Plaintext
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext harus berupa bytes atau bytearray.")

    plaintext_bytes = bytes(plaintext)

    # Validasi Associated Data jika ada
    if associated_data is not None and not isinstance(associated_data, (bytes, bytearray)):
        raise TypeError("Associated data harus berupa bytes jika disediakan.")
    aad_bytes = bytes(associated_data) if associated_data is not None else None

    # Hasilkan Nonce unik dan acak untuk operasi ini
    nonce = generate_nonce()

    # Inisialisasi cipher AESGCM dari library cryptography
    aesgcm = AESGCM(key)

    # Enkripsi: API cryptography mengembalikan (ciphertext + 16_byte_tag)
    encrypted_payload = aesgcm.encrypt(nonce, plaintext_bytes, aad_bytes)

    # Pisahkan ciphertext dan authentication tag 16-byte
    ciphertext = encrypted_payload[:-AES_TAG_LENGTH]
    tag = encrypted_payload[-AES_TAG_LENGTH:]

    return AESGCMResult(
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag
    )


def decrypt_aes_gcm(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    associated_data: Optional[bytes] = None
) -> bytes:
    """
    Helper fungsi verifikasi dan dekripsi internal untuk memvalidasi otentisitas data.
    Digunakan untuk unit testing dan integrasi modul pada tahap selanjutnya.

    Args:
        key (bytes): Kunci simetris 32-byte.
        nonce (bytes): Nonce 12-byte yang digunakan saat enkripsi.
        ciphertext (bytes): Ciphertext biner.
        tag (bytes): Authentication tag 16-byte.
        associated_data (Optional[bytes]): Data otentikasi tambahan (AAD).

    Returns:
        bytes: Plaintext asli jika tag valid.

    Raises:
        InvalidTag / ValueError: Jika ciphertext atau tag telah dimodifikasi atau key salah.
    """
    if not isinstance(key, bytes) or len(key) != AES_KEY_LENGTH:
        raise ValueError(f"Panjang key AES-256 harus tepat {AES_KEY_LENGTH} byte.")

    if not isinstance(nonce, bytes) or len(nonce) != AES_NONCE_LENGTH:
        raise ValueError(f"Panjang nonce harus tepat {AES_NONCE_LENGTH} byte.")

    if not isinstance(tag, bytes) or len(tag) != AES_TAG_LENGTH:
        raise ValueError(f"Panjang authentication tag harus tepat {AES_TAG_LENGTH} byte.")

    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext harus berupa bytes.")

    aad_bytes = bytes(associated_data) if associated_data is not None else None

    # Gabungkan ciphertext dan tag sesuai format yang diharapkan AESGCM.decrypt
    combined_payload = bytes(ciphertext) + bytes(tag)

    aesgcm = AESGCM(key)
    
    try:
        # Dekripsi dan autentikasi otomatis
        plaintext = aesgcm.decrypt(nonce, combined_payload, aad_bytes)
        return plaintext
    except InvalidTag:
        raise ValueError("Autentikasi gagal: ciphertext atau tag telah dimodifikasi (tampered), atau key tidak sesuai.")
