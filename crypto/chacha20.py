"""
SecureDrop - ChaCha20-Poly1305 Encryption Module
Mengimplementasikan Authenticated Encryption with Associated Data (AEAD) menggunakan ChaCha20-Poly1305
sesuai standar RFC 8439 dan memanfaatkan library cryptography teruji.
"""

import secrets
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

# ==============================================================================
# KONSTANTA KONFIGURASI KRIPTOGRAFI CHACHA20-POLY1305
# ==============================================================================

# Panjang kunci ChaCha20-Poly1305 dalam byte (32 byte = 256 bit).
CHACHA20_KEY_LENGTH: int = 32

# Panjang nonce standar untuk ChaCha20-Poly1305 (12 byte = 96 bit sesuai RFC 8439 / RFC 7539).
CHACHA20_NONCE_LENGTH: int = 12

# Panjang authentication tag Poly1305 standar (16 byte = 128 bit).
CHACHA20_TAG_LENGTH: int = 16


# ==============================================================================
# STRUKTUR DATA HASIL ENKRIPSI
# ==============================================================================

@dataclass(frozen=True)
class ChaCha20Result:
    """
    Struktur data container untuk memuat komponen hasil enkripsi ChaCha20-Poly1305.
    
    Attributes:
        nonce (bytes): Nonce acak 12-byte (96-bit) yang digunakan saat enkripsi.
        ciphertext (bytes): Data terenkripsi (panjang sama persis dengan plaintext).
        tag (bytes): Authentication Tag Poly1305 16-byte (128-bit) untuk verifikasi integritas.
    """
    nonce: bytes
    ciphertext: bytes
    tag: bytes


# ==============================================================================
# FUNGSI NONCE & ENKRIPSI CHACHA20-POLY1305
# ==============================================================================

def generate_nonce(length: int = CHACHA20_NONCE_LENGTH) -> bytes:
    """
    Menghasilkan nonce acak menggunakan CSPRNG (secrets.token_bytes).

    Args:
        length (int): Panjang nonce dalam byte (default: 12 byte).

    Returns:
        bytes: Nonce acak berukuran 12 byte.

    Raises:
        ValueError: Jika panjang nonce bukan 12 byte.
    """
    if not isinstance(length, int) or length != CHACHA20_NONCE_LENGTH:
        raise ValueError(f"Panjang nonce ChaCha20-Poly1305 harus tepat {CHACHA20_NONCE_LENGTH} byte (96 bit).")
    
    return secrets.token_bytes(length)


def encrypt_chacha20(
    key: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None
) -> ChaCha20Result:
    """
    Mengenkskripsi plaintext (binary/bytes) menggunakan algoritma ChaCha20-Poly1305.

    Alur:
        Plaintext (bytes) + 32-byte Key + Random 12-byte Nonce
        -> ChaCha20-Poly1305
        -> Ciphertext (bytes) + Authentication Tag (16 bytes)

    Args:
        key (bytes): Kunci simetris 256-bit (harus tepat 32 byte dari KDF).
        plaintext (bytes): Data biner yang akan dienkripsi.
        associated_data (Optional[bytes]): Data tambahan terotentikasi (AAD) opsional.

    Returns:
        ChaCha20Result: Objek yang memuat nonce (12B), ciphertext, dan tag (16B).

    Raises:
        TypeError: Jika tipe data key atau plaintext bukan bytes.
        ValueError: Jika panjang key tidak tepat 32 byte.
    """
    # Validasi Key
    if not isinstance(key, bytes):
        raise TypeError("Key harus bertipe bytes.")
    if len(key) != CHACHA20_KEY_LENGTH:
        raise ValueError(f"Panjang key ChaCha20-Poly1305 harus tepat {CHACHA20_KEY_LENGTH} byte (256 bit).")

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

    # Inisialisasi cipher ChaCha20Poly1305 dari library cryptography
    chacha = ChaCha20Poly1305(key)

    # Enkripsi: API cryptography mengembalikan (ciphertext + 16_byte_tag)
    encrypted_payload = chacha.encrypt(nonce, plaintext_bytes, aad_bytes)

    # Pisahkan ciphertext dan authentication tag 16-byte
    ciphertext = encrypted_payload[:-CHACHA20_TAG_LENGTH]
    tag = encrypted_payload[-CHACHA20_TAG_LENGTH:]

    return ChaCha20Result(
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag
    )


def decrypt_chacha20(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    associated_data: Optional[bytes] = None
) -> bytes:
    """
    Helper fungsi verifikasi dan dekripsi internal untuk memvalidasi otentisitas data.
    Digunakan untuk unit testing dan memastikan proses autentikasi Poly1305 bekerja.

    Args:
        key (bytes): Kunci simetris 32-byte.
        nonce (bytes): Nonce 12-byte yang digunakan saat enkripsi.
        ciphertext (bytes): Ciphertext biner.
        tag (bytes): Authentication tag 16-byte.
        associated_data (Optional[bytes]): Data otentikasi tambahan (AAD).

    Returns:
        bytes: Plaintext asli jika tag valid.

    Raises:
        TypeError: Jika parameter bukan bytes.
        ValueError: Jika ukuran parameter salah atau jika otentikasi gagal (tampered/wrong key).
    """
    if not isinstance(key, bytes) or len(key) != CHACHA20_KEY_LENGTH:
        raise ValueError(f"Panjang key ChaCha20-Poly1305 harus tepat {CHACHA20_KEY_LENGTH} byte.")

    if not isinstance(nonce, bytes) or len(nonce) != CHACHA20_NONCE_LENGTH:
        raise ValueError(f"Panjang nonce harus tepat {CHACHA20_NONCE_LENGTH} byte.")

    if not isinstance(tag, bytes) or len(tag) != CHACHA20_TAG_LENGTH:
        raise ValueError(f"Panjang authentication tag harus tepat {CHACHA20_TAG_LENGTH} byte.")

    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext harus berupa bytes.")

    aad_bytes = bytes(associated_data) if associated_data is not None else None

    # Gabungkan ciphertext dan tag sesuai format yang diharapkan ChaCha20Poly1305.decrypt
    combined_payload = bytes(ciphertext) + bytes(tag)

    chacha = ChaCha20Poly1305(key)
    
    try:
        # Dekripsi dan autentikasi otomatis
        plaintext = chacha.decrypt(nonce, combined_payload, aad_bytes)
        return plaintext
    except InvalidTag:
        raise ValueError("Autentikasi gagal: ciphertext atau tag telah dimodifikasi (tampered), atau key tidak sesuai.")
