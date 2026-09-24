"""
Unit test suite untuk modul enkripsi AES-256-GCM dan integrasi dengan KDF.
"""

import pytest
import secrets
from crypto.aes_gcm import (
    generate_nonce,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    AESGCMResult,
    AES_KEY_LENGTH,
    AES_NONCE_LENGTH,
    AES_TAG_LENGTH,
)
from crypto.kdf import generate_salt, derive_key


@pytest.fixture
def sample_key():
    """Fixture untuk menghasilkan 32-byte key menggunakan CSPRNG."""
    return secrets.token_bytes(32)


def test_nonce_length():
    """Test 1: Nonce yang dihasilkan berukuran tepat 12 byte (96 bit)."""
    nonce = generate_nonce()
    assert isinstance(nonce, bytes)
    assert len(nonce) == AES_NONCE_LENGTH
    assert len(nonce) == 12


def test_aes_key_length_validation():
    """Test 2: Fungsi enkripsi hanya menerima kunci 32-byte (256-bit)."""
    plaintext = b"Pesan rahasia untuk pengujian"
    
    # Kunci valid 32 byte
    valid_key = secrets.token_bytes(32)
    res = encrypt_aes_gcm(key=valid_key, plaintext=plaintext)
    assert isinstance(res, AESGCMResult)

    # Kunci tidak valid (16 byte atau 24 byte)
    invalid_key_16 = secrets.token_bytes(16)
    with pytest.raises(ValueError, match="tepat 32 byte"):
        encrypt_aes_gcm(key=invalid_key_16, plaintext=plaintext)

    # Kunci bertipe salah
    with pytest.raises(TypeError, match="bertipe bytes"):
        encrypt_aes_gcm(key="invalid_string_key_type", plaintext=plaintext)  # type: ignore


def test_encryption_produces_ciphertext(sample_key):
    """Test 3: Enkripsi menghasilkan ciphertext yang tidak sama dengan plaintext."""
    plaintext = b"Data dokumen rahasia SecureDrop 2026"
    res = encrypt_aes_gcm(key=sample_key, plaintext=plaintext)
    
    assert res.ciphertext != plaintext
    assert len(res.ciphertext) == len(plaintext)
    assert isinstance(res.ciphertext, bytes)


def test_ciphertext_different_on_second_encryption(sample_key):
    """Test 4: Nonce dan ciphertext selalu berbeda pada setiap proses enkripsi (mencegah nonce reuse)."""
    plaintext = b"Pesan yang sama dienkripsi dua kali"
    
    res1 = encrypt_aes_gcm(key=sample_key, plaintext=plaintext)
    res2 = encrypt_aes_gcm(key=sample_key, plaintext=plaintext)
    
    assert res1.nonce != res2.nonce
    assert res1.ciphertext != res2.ciphertext


def test_authentication_tag_length(sample_key):
    """Test 5: Authentication tag berukuran tepat 16 byte (128 bit)."""
    plaintext = b"Verifikasi authentication tag"
    res = encrypt_aes_gcm(key=sample_key, plaintext=plaintext)
    
    assert isinstance(res.tag, bytes)
    assert len(res.tag) == AES_TAG_LENGTH
    assert len(res.tag) == 16


def test_tampered_ciphertext_rejected(sample_key):
    """Test 6: Modifikasi 1 byte pada ciphertext menyebabkan kegagalan autentikasi."""
    plaintext = b"Pesan penting yang tidak boleh diubah sedikitpun"
    res = encrypt_aes_gcm(key=sample_key, plaintext=plaintext)
    
    # Modifikasi 1 byte pertama pada ciphertext
    tampered_bytes = bytearray(res.ciphertext)
    tampered_bytes[0] ^= 0xFF
    tampered_ciphertext = bytes(tampered_bytes)
    
    with pytest.raises(ValueError, match="Autentikasi gagal"):
        decrypt_aes_gcm(
            key=sample_key,
            nonce=res.nonce,
            ciphertext=tampered_ciphertext,
            tag=res.tag
        )


def test_tampered_authentication_tag_rejected(sample_key):
    """Test 7: Modifikasi 1 byte pada authentication tag menyebabkan penolakan dekripsi."""
    plaintext = b"Pesan dengan tag otentikasi"
    res = encrypt_aes_gcm(key=sample_key, plaintext=plaintext)
    
    # Modifikasi 1 byte pada tag
    tampered_tag_bytes = bytearray(res.tag)
    tampered_tag_bytes[-1] ^= 0xFF
    tampered_tag = bytes(tampered_tag_bytes)
    
    with pytest.raises(ValueError, match="Autentikasi gagal"):
        decrypt_aes_gcm(
            key=sample_key,
            nonce=res.nonce,
            ciphertext=res.ciphertext,
            tag=tampered_tag
        )


def test_wrong_key_rejected(sample_key):
    """Test 8: Kunci yang salah ditolak dan proses autentikasi gagal."""
    plaintext = b"Pesan rahasia"
    res = encrypt_aes_gcm(key=sample_key, plaintext=plaintext)
    
    wrong_key = secrets.token_bytes(32)
    while wrong_key == sample_key:
        wrong_key = secrets.token_bytes(32)
        
    with pytest.raises(ValueError, match="Autentikasi gagal"):
        decrypt_aes_gcm(
            key=wrong_key,
            nonce=res.nonce,
            ciphertext=res.ciphertext,
            tag=res.tag
        )


def test_binary_data_encryption(sample_key):
    """Test 9: Enkripsi mendukung data biner arbitrer (termasuk byte null dan nilai 0-255)."""
    # Simulasi header file binary / gambar / PDF
    binary_data = bytes([0x00, 0xFF, 0xFE, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00])
    
    res = encrypt_aes_gcm(key=sample_key, plaintext=binary_data)
    decrypted = decrypt_aes_gcm(
        key=sample_key,
        nonce=res.nonce,
        ciphertext=res.ciphertext,
        tag=res.tag
    )
    
    assert decrypted == binary_data


def test_integration_kdf_with_aes_gcm():
    """Test 10: Integrasi alur Password -> KDF (PBKDF2) -> Key -> AES-256-GCM -> Verifikasi."""
    user_password = "PasswordMahasiswaKripto2026!"
    salt = generate_salt()
    
    # 1. Derivasi Kunci 32 byte via PBKDF2
    derived_key = derive_key(password=user_password, salt=salt, iterations=100_000)
    assert len(derived_key) == 32
    
    # 2. Enkripsi AES-256-GCM menggunakan Derived Key
    plaintext = b"Laporan Tugas Besar Keamanan Informasi SecureDrop"
    res = encrypt_aes_gcm(key=derived_key, plaintext=plaintext)
    
    # 3. Verifikasi Dekripsi
    decrypted = decrypt_aes_gcm(
        key=derived_key,
        nonce=res.nonce,
        ciphertext=res.ciphertext,
        tag=res.tag
    )
    
    assert decrypted == plaintext
