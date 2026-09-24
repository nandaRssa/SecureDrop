import secrets
from typing import Union
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# konfigurasi default kdf
SALT_LENGTH: int = 16
KEY_LENGTH: int = 32
PBKDF2_ITERATIONS: int = 600_000


# GENERATE RANDOM SALT
def generate_salt(length: int = SALT_LENGTH) -> bytes:
    # panjang salt minimal 16 byte
    if not isinstance(length, int) or length < 16:
        raise ValueError("Panjang salt minimal harus 16 byte.")
    
    # generate salt pakai csprng
    return secrets.token_bytes(length)


# DERIVASI KEY DARI PASSWORD DAN SALT (PBKDF2-HMAC-SHA256)
def derive_key(
    password: Union[str, bytes],
    salt: bytes,
    iterations: int = PBKDF2_ITERATIONS,
    length: int = KEY_LENGTH
) -> bytes:
    # validasi password
    if password is None:
        raise TypeError("Password tidak boleh bernilai None.")

    if isinstance(password, str):
        if len(password) == 0:
            raise ValueError("Password tidak boleh kosong.")
        # ubah string password ke bytes
        password_bytes = password.encode("utf-8")
    elif isinstance(password, bytes):
        if len(password) == 0:
            raise ValueError("Password bytes tidak boleh kosong.")
        password_bytes = password
    else:
        raise TypeError("Password harus berupa string atau bytes.")

    # validasi salt
    if not isinstance(salt, bytes):
        raise TypeError("Salt harus bertipe bytes.")

    if len(salt) < 16:
        raise ValueError("Salt harus memiliki panjang minimal 16 byte.")

    # validasi iterasi dan panjang key
    if not isinstance(iterations, int) or iterations < 100_000:
        raise ValueError("Jumlah iterasi minimal adalah 100.000.")

    if not isinstance(length, int) or length != 32:
        raise ValueError("Panjang derived key harus tepat 32 byte (256 bit).")

    # setup pbkdf2 pakai sha256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )

    # proses derivasi key
    derived_key = kdf.derive(password_bytes)

    return derived_key
