import secrets
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# konstanta aes-gcm
AES_KEY_LENGTH: int = 32
AES_NONCE_LENGTH: int = 12
AES_TAG_LENGTH: int = 16


# STRUKTUR HASIL ENKRIPSI AES-GCM
@dataclass(frozen=True)
class AESGCMResult:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


# GENERATE NONCE 12 BYTE UNTUK AES-GCM
def generate_nonce(length: int = AES_NONCE_LENGTH) -> bytes:
    # nonce aes-gcm harus 12 byte (96 bit)
    if not isinstance(length, int) or length != AES_NONCE_LENGTH:
        raise ValueError(f"Panjang nonce AES-GCM harus tepat {AES_NONCE_LENGTH} byte (96 bit).")
    
    # generate nonce acak dengan csprng
    return secrets.token_bytes(length)


# ENKRIPSI DATA MENGGUNAKAN AES-256-GCM
def encrypt_aes_gcm(
    key: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None
) -> AESGCMResult:
    # validasi key 32 byte
    if not isinstance(key, bytes):
        raise TypeError("Key harus bertipe bytes.")
    if len(key) != AES_KEY_LENGTH:
        raise ValueError(f"Panjang key AES-256 harus tepat {AES_KEY_LENGTH} byte (256 bit).")

    # validasi data plaintext
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext harus berupa bytes atau bytearray.")

    plaintext_bytes = bytes(plaintext)

    # validasi aad jika ada
    if associated_data is not None and not isinstance(associated_data, (bytes, bytearray)):
        raise TypeError("Associated data harus berupa bytes jika disediakan.")
    aad_bytes = bytes(associated_data) if associated_data is not None else None

    # buat nonce baru setiap enkripsi
    nonce = generate_nonce()

    # inisialisasi aesgcm cipher
    aesgcm = AESGCM(key)

    # enkripsi menghasilkan gabungan ciphertext + tag 16 byte
    encrypted_payload = aesgcm.encrypt(nonce, plaintext_bytes, aad_bytes)

    # pisahkan ciphertext dan authentication tag 16 byte
    ciphertext = encrypted_payload[:-AES_TAG_LENGTH]
    tag = encrypted_payload[-AES_TAG_LENGTH:]

    return AESGCMResult(
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag
    )


# DEKRIPSI DAN VERIFIKASI INTERNAL AES-256-GCM
def decrypt_aes_gcm(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    associated_data: Optional[bytes] = None
) -> bytes:
    # validasi parameter
    if not isinstance(key, bytes) or len(key) != AES_KEY_LENGTH:
        raise ValueError(f"Panjang key AES-256 harus tepat {AES_KEY_LENGTH} byte.")

    if not isinstance(nonce, bytes) or len(nonce) != AES_NONCE_LENGTH:
        raise ValueError(f"Panjang nonce harus tepat {AES_NONCE_LENGTH} byte.")

    if not isinstance(tag, bytes) or len(tag) != AES_TAG_LENGTH:
        raise ValueError(f"Panjang authentication tag harus tepat {AES_TAG_LENGTH} byte.")

    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext harus berupa bytes.")

    aad_bytes = bytes(associated_data) if associated_data is not None else None

    # gabungkan kembali ciphertext dan tag
    combined_payload = bytes(ciphertext) + bytes(tag)

    aesgcm = AESGCM(key)
    
    try:
        # dekripsi sekaligus cek integritas tag
        plaintext = aesgcm.decrypt(nonce, combined_payload, aad_bytes)
        return plaintext
    except InvalidTag:
        raise ValueError("Autentikasi gagal: ciphertext atau tag telah dimodifikasi (tampered), atau key tidak sesuai.")
