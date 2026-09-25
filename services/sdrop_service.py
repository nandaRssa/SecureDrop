"""SecureDrop package, password decryption, and hybrid RSA-OAEP services."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Optional, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.aes_gcm import decrypt_aes_gcm
from crypto.chacha20 import decrypt_chacha20
from crypto.kdf import derive_key
from services.encryption_service import (
    ALGO_AES_GCM,
    ALGO_CHACHA20,
    EncryptionResult,
)

SDROP_FORMAT = "SecureDrop"
SDROP_VERSION = 1
MODE_PASSWORD = "password"
MODE_HYBRID = "hybrid"
_RSA_OAEP_LABEL = b"SecureDrop hybrid AES key v1"


class SdropFormatError(ValueError):
    """Raised when a .sdrop payload is invalid or incomplete."""


class AuthenticationError(ValueError):
    """Raised when authentication or key verification fails."""


@dataclass(frozen=True)
class SdropPackage:
    mode: str
    algorithm: str
    original_filename: str
    file_size: int
    salt: Optional[bytes]
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    encrypted_key: Optional[bytes] = None


def _b64_encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64_decode(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise SdropFormatError(f"Field {field} harus berupa Base64 string.")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise SdropFormatError(f"Field {field} bukan Base64 yang valid.") from exc


def _validate_common(package: SdropPackage) -> None:
    if package.algorithm not in (ALGO_AES_GCM, ALGO_CHACHA20):
        raise SdropFormatError("Algoritma dalam .sdrop tidak didukung.")
    if not package.original_filename or "\x00" in package.original_filename:
        raise SdropFormatError("Nama file dalam .sdrop tidak valid.")
    if package.file_size <= 0 or len(package.ciphertext) != package.file_size:
        raise SdropFormatError("Ukuran ciphertext tidak sesuai metadata.")
    if len(package.nonce) != 12 or len(package.tag) != 16:
        raise SdropFormatError("Nonce atau authentication tag memiliki panjang tidak valid.")
    if package.mode == MODE_PASSWORD and (package.salt is None or len(package.salt) != 16):
        raise SdropFormatError("Salt password tidak valid.")
    if package.mode == MODE_HYBRID and (package.salt is not None or not package.encrypted_key):
        raise SdropFormatError("Kunci hybrid tidak lengkap.")


def package_encryption_result(result: EncryptionResult) -> bytes:
    """Serialize an O1 EncryptionResult to a versioned .sdrop payload."""
    package = SdropPackage(
        mode=MODE_PASSWORD,
        algorithm=result.algorithm,
        original_filename=result.original_filename,
        file_size=result.file_size,
        salt=result.salt,
        nonce=result.nonce,
        ciphertext=result.ciphertext,
        tag=result.tag,
    )
    _validate_common(package)
    document = {
        "format": SDROP_FORMAT,
        "version": SDROP_VERSION,
        "mode": package.mode,
        "algorithm": package.algorithm,
        "original_filename": package.original_filename,
        "file_size": package.file_size,
        "salt": _b64_encode(package.salt),
        "nonce": _b64_encode(package.nonce),
        "ciphertext": _b64_encode(package.ciphertext),
        "tag": _b64_encode(package.tag),
    }
    return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def read_sdrop(data: Union[bytes, bytearray]) -> SdropPackage:
    """Parse and validate a .sdrop payload without decrypting it."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise SdropFormatError("File .sdrop kosong atau bukan data biner.")
    try:
        document = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SdropFormatError("Format .sdrop rusak atau bukan JSON UTF-8.") from exc
    if not isinstance(document, dict):
        raise SdropFormatError("Root .sdrop harus berupa object JSON.")
    if document.get("format") != SDROP_FORMAT or document.get("version") != SDROP_VERSION:
        raise SdropFormatError("Format atau versi .sdrop tidak didukung.")

    mode = document.get("mode")
    if mode not in (MODE_PASSWORD, MODE_HYBRID):
        raise SdropFormatError("Mode .sdrop tidak didukung.")
    try:
        package = SdropPackage(
            mode=mode,
            algorithm=document["algorithm"],
            original_filename=document["original_filename"],
            file_size=document["file_size"],
            salt=_b64_decode(document["salt"], "salt") if mode == MODE_PASSWORD else None,
            nonce=_b64_decode(document["nonce"], "nonce"),
            ciphertext=_b64_decode(document["ciphertext"], "ciphertext"),
            tag=_b64_decode(document["tag"], "tag"),
            encrypted_key=_b64_decode(document["encrypted_key"], "encrypted_key") if mode == MODE_HYBRID else None,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SdropFormatError("Field wajib .sdrop tidak lengkap atau tidak valid.") from exc
    if not isinstance(package.file_size, int) or isinstance(package.file_size, bool):
        raise SdropFormatError("file_size harus berupa integer.")
    _validate_common(package)
    return package


def decrypt_sdrop(data: Union[bytes, bytearray], password: Union[str, bytes]) -> tuple[bytes, str]:
    """Decrypt a password-based .sdrop and verify its AEAD tag."""
    package = read_sdrop(data)
    if package.mode != MODE_PASSWORD:
        raise SdropFormatError("Gunakan decrypt_hybrid_sdrop untuk paket hybrid.")
    try:
        key = derive_key(password, package.salt)  # type: ignore[arg-type]
        if package.algorithm == ALGO_AES_GCM:
            plaintext = decrypt_aes_gcm(key, package.nonce, package.ciphertext, package.tag)
        else:
            plaintext = decrypt_chacha20(key, package.nonce, package.ciphertext, package.tag)
    except (ValueError, TypeError) as exc:
        raise AuthenticationError("Authentication Failed: password salah atau ciphertext berubah.") from exc
    if len(plaintext) != package.file_size:
        raise AuthenticationError("Authentication Failed: ukuran plaintext tidak sesuai metadata.")
    return plaintext, package.original_filename


def generate_rsa_key_pair(key_size: int = 2048) -> tuple[bytes, bytes]:
    """Generate an RSA-OAEP key pair at runtime as PEM bytes."""
    if key_size < 2048:
        raise ValueError("Ukuran RSA minimal adalah 2048 bit.")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_bytes, public_bytes


def _load_public_key(key: Union[bytes, rsa.RSAPublicKey]) -> rsa.RSAPublicKey:
    if isinstance(key, rsa.RSAPublicKey):
        return key
    loaded = serialization.load_pem_public_key(key)
    if not isinstance(loaded, rsa.RSAPublicKey):
        raise TypeError("Public key harus berupa RSA key.")
    return loaded


def _load_private_key(key: Union[bytes, rsa.RSAPrivateKey]) -> rsa.RSAPrivateKey:
    if isinstance(key, rsa.RSAPrivateKey):
        return key
    loaded = serialization.load_pem_private_key(key, password=None)
    if not isinstance(loaded, rsa.RSAPrivateKey):
        raise TypeError("Private key harus berupa RSA key.")
    return loaded


def create_hybrid_sdrop(
    file_bytes: Union[bytes, bytearray],
    public_key: Union[bytes, rsa.RSAPublicKey],
    algorithm: str = ALGO_AES_GCM,
    original_filename: str = "document",
) -> bytes:
    """Encrypt file with a random AES-256 session key wrapped by RSA-OAEP."""
    raw = bytes(file_bytes)
    if not raw:
        raise ValueError("File tidak boleh kosong.")
    if algorithm != ALGO_AES_GCM:
        raise ValueError("Algoritma hybrid harus AES-256-GCM.")
    from crypto.aes_gcm import generate_nonce as generate_aes_nonce
    import secrets

    session_key = secrets.token_bytes(32)
    nonce = generate_aes_nonce()
    encrypted = AESGCM(session_key).encrypt(nonce, raw, None)
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    wrapped_key = _load_public_key(public_key).encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=_RSA_OAEP_LABEL),
    )
    package = SdropPackage(MODE_HYBRID, algorithm, str(original_filename).strip() or "document", len(raw), None, nonce, ciphertext, tag, wrapped_key)
    _validate_common(package)
    document = {
        "format": SDROP_FORMAT, "version": SDROP_VERSION, "mode": MODE_HYBRID,
        "algorithm": package.algorithm, "original_filename": package.original_filename,
        "file_size": package.file_size, "encrypted_key": _b64_encode(wrapped_key),
        "nonce": _b64_encode(nonce), "ciphertext": _b64_encode(ciphertext), "tag": _b64_encode(tag),
    }
    return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decrypt_hybrid_sdrop(data: Union[bytes, bytearray], private_key: Union[bytes, rsa.RSAPrivateKey]) -> tuple[bytes, str]:
    package = read_sdrop(data)
    if package.mode != MODE_HYBRID or package.encrypted_key is None:
        raise SdropFormatError("Paket bukan .sdrop hybrid.")
    try:
        session_key = _load_private_key(private_key).decrypt(
            package.encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=_RSA_OAEP_LABEL),
        )
        plaintext = AESGCM(session_key).decrypt(package.nonce, package.ciphertext + package.tag, None)
    except Exception as exc:
        raise AuthenticationError("Authentication Failed: private key salah atau ciphertext berubah.") from exc
    if len(plaintext) != package.file_size:
        raise AuthenticationError("Authentication Failed: ukuran plaintext tidak sesuai metadata.")
    return plaintext, package.original_filename
