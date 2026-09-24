from dataclasses import dataclass
from typing import Union, Optional
from crypto.kdf import generate_salt, derive_key
from crypto.aes_gcm import encrypt_aes_gcm
from crypto.chacha20 import encrypt_chacha20

# pilihan cipher yang didukung
ALGO_AES_GCM: str = "AES-256-GCM"
ALGO_CHACHA20: str = "ChaCha20-Poly1305"
SUPPORTED_ALGORITHMS = (ALGO_AES_GCM, ALGO_CHACHA20)


# STRUKTUR DATA PENAMPUNG HASIL ENKRIPSI
@dataclass(frozen=True)
class EncryptionResult:
    algorithm: str
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    original_filename: str
    file_size: int


# SERVICE ENKRIPSI FILE
def encrypt_file_data(
    file_bytes: Union[bytes, bytearray],
    password: Union[str, bytes],
    algorithm: str = ALGO_AES_GCM,
    original_filename: str = "document",
    associated_data: Optional[bytes] = None
) -> EncryptionResult:
    # 1. cek data file
    if file_bytes is None:
        raise ValueError("File tidak ditemukan.")

    if not isinstance(file_bytes, (bytes, bytearray)):
        raise TypeError("Data file harus berupa bytes atau bytearray.")

    raw_bytes = bytes(file_bytes)
    if len(raw_bytes) == 0:
        raise ValueError("File tidak boleh kosong.")

    # 2. cek password
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

    # 3. cek algoritma yang dipilih
    if not isinstance(algorithm, str):
        raise TypeError("Algoritma harus berupa string.")

    cleaned_algo = algorithm.strip()
    if cleaned_algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algoritma tidak valid: '{algorithm}'. Pilihan yang didukung: {', '.join(SUPPORTED_ALGORITHMS)}.")

    # 4. generate salt acak dan derivasi key dengan pbkdf2
    salt = generate_salt()
    derived_key = derive_key(password=password, salt=salt)

    # 5. eksekusi enkripsi sesuai cipher pilihan
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
