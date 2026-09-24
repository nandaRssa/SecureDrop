import secrets
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

# konstanta chacha20-poly1305
CHACHA20_KEY_LENGTH: int = 32
CHACHA20_NONCE_LENGTH: int = 12
CHACHA20_TAG_LENGTH: int = 16


# STRUKTUR HASIL ENKRIPSI CHACHA20-POLY1305
@dataclass(frozen=True)
class ChaCha20Result:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


# GENERATE NONCE 12 BYTE UNTUK CHACHA20
def generate_nonce(length: int = CHACHA20_NONCE_LENGTH) -> bytes:
    # nonce chacha20 harus 12 byte (96 bit)
    if not isinstance(length, int) or length != CHACHA20_NONCE_LENGTH:
        raise ValueError(f"Panjang nonce ChaCha20-Poly1305 harus tepat {CHACHA20_NONCE_LENGTH} byte (96 bit).")
    
    # generate nonce acak dengan csprng
    return secrets.token_bytes(length)


# ENKRIPSI DATA MENGGUNAKAN CHACHA20-POLY1305
def encrypt_chacha20(
    key: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None
) -> ChaCha20Result:
    # validasi key 32 byte
    if not isinstance(key, bytes):
        raise TypeError("Key harus bertipe bytes.")
    if len(key) != CHACHA20_KEY_LENGTH:
        raise ValueError(f"Panjang key ChaCha20-Poly1305 harus tepat {CHACHA20_KEY_LENGTH} byte (256 bit).")

    # validasi plaintext
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext harus berupa bytes atau bytearray.")

    plaintext_bytes = bytes(plaintext)

    # validasi aad jika ada
    if associated_data is not None and not isinstance(associated_data, (bytes, bytearray)):
        raise TypeError("Associated data harus berupa bytes jika disediakan.")
    aad_bytes = bytes(associated_data) if associated_data is not None else None

    # buat nonce baru setiap enkripsi
    nonce = generate_nonce()

    # inisialisasi cipher chacha20-poly1305
    chacha = ChaCha20Poly1305(key)

    # enkripsi payload (ciphertext + tag 16 byte)
    encrypted_payload = chacha.encrypt(nonce, plaintext_bytes, aad_bytes)

    # pisahkan ciphertext dan tag otentikasi
    ciphertext = encrypted_payload[:-CHACHA20_TAG_LENGTH]
    tag = encrypted_payload[-CHACHA20_TAG_LENGTH:]

    return ChaCha20Result(
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag
    )


# DEKRIPSI DAN VERIFIKASI INTERNAL CHACHA20-POLY1305
def decrypt_chacha20(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    associated_data: Optional[bytes] = None
) -> bytes:
    # validasi parameter
    if not isinstance(key, bytes) or len(key) != CHACHA20_KEY_LENGTH:
        raise ValueError(f"Panjang key ChaCha20-Poly1305 harus tepat {CHACHA20_KEY_LENGTH} byte.")

    if not isinstance(nonce, bytes) or len(nonce) != CHACHA20_NONCE_LENGTH:
        raise ValueError(f"Panjang nonce harus tepat {CHACHA20_NONCE_LENGTH} byte.")

    if not isinstance(tag, bytes) or len(tag) != CHACHA20_TAG_LENGTH:
        raise ValueError(f"Panjang authentication tag harus tepat {CHACHA20_TAG_LENGTH} byte.")

    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext harus berupa bytes.")

    aad_bytes = bytes(associated_data) if associated_data is not None else None

    # gabungkan kembali ciphertext dan tag
    combined_payload = bytes(ciphertext) + bytes(tag)

    chacha = ChaCha20Poly1305(key)
    
    try:
        # dekripsi sekaligus verifikasi integritas
        plaintext = chacha.decrypt(nonce, combined_payload, aad_bytes)
        return plaintext
    except InvalidTag:
        raise ValueError("Autentikasi gagal: ciphertext atau tag telah dimodifikasi (tampered), atau key tidak sesuai.")
