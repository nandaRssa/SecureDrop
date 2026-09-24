"""
SecureDrop - Encryption Service Module (Tahap 5: Integrasi Encrypt & Send)
Menyediakan layer abstraksi / service integrasi yang menghubungkan:
Input User (File Bytes + Password + Selected Cipher) -> KDF (PBKDF2) -> Key -> Selected Cipher -> EncryptionResult
"""

from dataclasses import dataclass
from typing import Union, Optional
from crypto.kdf import generate_salt, derive_key
from crypto.aes_gcm import encrypt_aes_gcm
from crypto.chacha20 import encrypt_chacha20

# Konstanta algoritma yang didukung
ALGO_AES_GCM: str = "AES-256-GCM"
ALGO_CHACHA20: str = "ChaCha20-Poly1305"
SUPPORTED_ALGORITHMS = (ALGO_AES_GCM, ALGO_CHACHA20)


@dataclass(frozen=True)
class EncryptionResult:
    """
    Data container internal untuk hasil enkripsi layer service.
    Memuat seluruh komponen kriptografi yang dibutuhkan sebelum tahap packaging .sdrop (Orang 2).

    Attributes:
        algorithm (str): Algoritma yang digunakan (AES-256-GCM / ChaCha20-Poly1305).
        salt (bytes): Random salt 16-byte dari CSPRNG.
        nonce (bytes): Random nonce 12-byte dari CSPRNG.
        ciphertext (bytes): Data terenkripsi.
        tag (bytes): Authentication tag 16-byte.
        original_filename (str): Nama asli file yang dienkripsi.
        file_size (int): Ukuran asli file dalam byte.
    """
    algorithm: str
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    original_filename: str
    file_size: int


def encrypt_file_data(
    file_bytes: Union[bytes, bytearray],
    password: Union[str, bytes],
    algorithm: str = ALGO_AES_GCM,
    original_filename: str = "document",
    associated_data: Optional[bytes] = None
) -> EncryptionResult:
    """
    Menghubungkan input data file biner, password, dan cipher pilihan ke modul core encryption.

    Alur:
        1. Validasi input (file tidak kosong, password terisi, algoritma valid).
        2. Generate 16-byte random salt via CSPRNG.
        3. Derivasi 32-byte key via PBKDF2-HMAC-SHA256 (600.000 iterasi).
        4. Generate 12-byte random nonce via CSPRNG & jalankan cipher terpilih.
        5. Kembalikan EncryptionResult internal.

    Args:
        file_bytes (Union[bytes, bytearray]): Isi data file dalam format biner.
        password (Union[str, bytes]): Password pengguna.
        algorithm (str): Pilihan algoritma ('AES-256-GCM' atau 'ChaCha20-Poly1305').
        original_filename (str): Nama file asli untuk identifikasi metadata.
        associated_data (Optional[bytes]): Data tambahan terotentikasi (opsional).

    Returns:
        EncryptionResult: Objek penampung seluruh artefak enkripsi.

    Raises:
        ValueError: Jika file kosong, password kosong, atau algoritma tidak valid.
        TypeError: Jika tipe parameter tidak sesuai.
    """
    # 1. Validasi File Data
    if file_bytes is None:
        raise ValueError("File tidak ditemukan.")

    if not isinstance(file_bytes, (bytes, bytearray)):
        raise TypeError("Data file harus berupa bytes atau bytearray.")

    raw_bytes = bytes(file_bytes)
    if len(raw_bytes) == 0:
        raise ValueError("File tidak boleh kosong.")

    # 2. Validasi Password
    if password is None:
        raise ValueError("Password wajib diisi.")

    if isinstance(password, str):
        if len(password.strip()) == 0:
            raise ValueError("Password wajib diisi.")
    elif isinstance(password, bytes):
        if len(password) == 0:
            raise ValueError("Password wajib diisi.")
    else:
        raise TypeError("Password harus berupa string atau bytes.")

    # 3. Validasi Algoritma
    if not isinstance(algorithm, str):
        raise TypeError("Algoritma harus berupa string.")

    cleaned_algo = algorithm.strip()
    if cleaned_algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algoritma tidak valid: '{algorithm}'. Pilihan yang didukung: {', '.join(SUPPORTED_ALGORITHMS)}.")

    # 4. Derivasi Kunci Kriptografi
    # Salt 16-byte unik digenerate baru setiap proses enkripsi
    salt = generate_salt()
    derived_key = derive_key(password=password, salt=salt)

    # 5. Eksekusi Enkripsi Sesuai Algoritma Terpilih
    if cleaned_algo == ALGO_AES_GCM:
        cipher_result = encrypt_aes_gcm(
            key=derived_key,
            plaintext=raw_bytes,
            associated_data=associated_data
        )
    elif cleaned_algo == ALGO_CHACHA20:
        cipher_result = encrypt_chacha20(
            key=derived_key,
            plaintext=raw_bytes,
            associated_data=associated_data
        )
    else:
        raise ValueError("Algoritma tidak didukung.")

    # Nama file default jika tidak diberikan
    safe_filename = str(original_filename).strip() if original_filename else "document"

    return EncryptionResult(
        algorithm=cleaned_algo,
        salt=salt,
        nonce=cipher_result.nonce,
        ciphertext=cipher_result.ciphertext,
        tag=cipher_result.tag,
        original_filename=safe_filename,
        file_size=len(raw_bytes)
    )
