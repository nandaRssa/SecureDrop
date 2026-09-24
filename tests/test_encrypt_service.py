"""
Unit and integration test suite untuk Encryption Service (Tahap 5).
Menguji integrasi alur: File Bytes + Password + Selected Cipher -> KDF -> Key -> Cipher -> EncryptionResult
"""

import io
import pytest
from services.encryption_service import (
    encrypt_file_data,
    EncryptionResult,
    ALGO_AES_GCM,
    ALGO_CHACHA20,
)
from crypto.aes_gcm import decrypt_aes_gcm
from crypto.chacha20 import decrypt_chacha20
from crypto.kdf import derive_key
from app import create_app


@pytest.fixture
def client():
    """Fixture Flask test client."""
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_encrypt_valid_file_aes_gcm():
    """Test 1: Upload file valid dengan AES-256-GCM berhasil dienkripsi."""
    file_bytes = b"Dokumen penting rahasia SecureDrop 2026."
    password = "KunciRahasiaAES123!"
    
    result = encrypt_file_data(
        file_bytes=file_bytes,
        password=password,
        algorithm=ALGO_AES_GCM,
        original_filename="rahasia.txt"
    )
    
    assert isinstance(result, EncryptionResult)
    assert result.algorithm == ALGO_AES_GCM
    assert result.original_filename == "rahasia.txt"
    assert result.file_size == len(file_bytes)
    assert result.ciphertext != file_bytes
    assert len(result.ciphertext) == len(file_bytes)


def test_encrypt_valid_file_chacha20():
    """Test 2: Upload file valid dengan ChaCha20-Poly1305 berhasil dienkripsi."""
    file_bytes = b"Dokumen penting rahasia ChaCha20."
    password = "KunciRahasiaChaCha456!"
    
    result = encrypt_file_data(
        file_bytes=file_bytes,
        password=password,
        algorithm=ALGO_CHACHA20,
        original_filename="laporan.pdf"
    )
    
    assert isinstance(result, EncryptionResult)
    assert result.algorithm == ALGO_CHACHA20
    assert result.original_filename == "laporan.pdf"
    assert result.file_size == len(file_bytes)
    assert result.ciphertext != file_bytes
    assert len(result.ciphertext) == len(file_bytes)


def test_empty_password_rejected():
    """Test 3: Password kosong ditolak dengan error yang jelas."""
    file_bytes = b"Isi dokumen"
    
    with pytest.raises(ValueError, match="Password wajib diisi"):
        encrypt_file_data(file_bytes=file_bytes, password="", algorithm=ALGO_AES_GCM)

    with pytest.raises(ValueError, match="Password wajib diisi"):
        encrypt_file_data(file_bytes=file_bytes, password="   ", algorithm=ALGO_AES_GCM)

    with pytest.raises(ValueError, match="Password wajib diisi"):
        encrypt_file_data(file_bytes=file_bytes, password=None, algorithm=ALGO_AES_GCM)  # type: ignore


def test_empty_file_rejected():
    """Test 4: File kosong (0 byte) ditolak."""
    password = "PasswordValid123!"
    
    with pytest.raises(ValueError, match="File tidak boleh kosong"):
        encrypt_file_data(file_bytes=b"", password=password, algorithm=ALGO_AES_GCM)

    with pytest.raises(ValueError, match="File tidak ditemukan"):
        encrypt_file_data(file_bytes=None, password=password, algorithm=ALGO_AES_GCM)  # type: ignore


def test_unsupported_algorithm_rejected():
    """Test 5: Algoritma yang tidak didukung (e.g. DES, ECB, RC4) ditolak."""
    file_bytes = b"Isi dokumen uji"
    password = "PasswordValid123!"
    
    unsupported_algos = ["AES-ECB", "DES", "RC4", "TripleDES", "Blowfish", "UnknownCipher"]
    for algo in unsupported_algos:
        with pytest.raises(ValueError, match="Algoritma tidak valid"):
            encrypt_file_data(file_bytes=file_bytes, password=password, algorithm=algo)


def test_binary_data_processed_without_data_corruption():
    """Test 6: File binary arbitrer (PDF/JPG/PNG/ZIP) diproses tanpa perubahan atau konversi teks."""
    # Data biner representasi header binary berbagai format
    binary_content = bytes([
        0x00, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # Header PNG
        0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37,        # Header PDF
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46,        # Header JPG
        0x50, 0x4B, 0x03, 0x04,                                # Header ZIP
        0x00, 0x7F, 0x80, 0xFE, 0xFF                           # Byte boundary
    ])
    password = "BinaryPasswordTest2026!"
    
    # Uji dengan AES-256-GCM
    res_aes = encrypt_file_data(file_bytes=binary_content, password=password, algorithm=ALGO_AES_GCM)
    key_aes = derive_key(password, res_aes.salt)
    decrypted_aes = decrypt_aes_gcm(key_aes, res_aes.nonce, res_aes.ciphertext, res_aes.tag)
    assert decrypted_aes == binary_content

    # Uji dengan ChaCha20-Poly1305
    res_chacha = encrypt_file_data(file_bytes=binary_content, password=password, algorithm=ALGO_CHACHA20)
    key_chacha = derive_key(password, res_chacha.salt)
    decrypted_chacha = decrypt_chacha20(key_chacha, res_chacha.nonce, res_chacha.ciphertext, res_chacha.tag)
    assert decrypted_chacha == binary_content


def test_aes_result_has_all_components():
    """Test 7: Hasil AES memiliki salt 16B, nonce 12B, ciphertext, dan auth tag 16B."""
    file_bytes = b"Testing komponen hasil enkripsi AES-GCM"
    password = "PasswordKomponen123!"
    
    result = encrypt_file_data(file_bytes=file_bytes, password=password, algorithm=ALGO_AES_GCM)
    
    assert isinstance(result.salt, bytes) and len(result.salt) == 16
    assert isinstance(result.nonce, bytes) and len(result.nonce) == 12
    assert isinstance(result.ciphertext, bytes) and len(result.ciphertext) == len(file_bytes)
    assert isinstance(result.tag, bytes) and len(result.tag) == 16


def test_chacha_result_has_all_components():
    """Test 8: Hasil ChaCha memiliki salt 16B, nonce 12B, ciphertext, dan auth tag 16B."""
    file_bytes = b"Testing komponen hasil enkripsi ChaCha20"
    password = "PasswordKomponen456!"
    
    result = encrypt_file_data(file_bytes=file_bytes, password=password, algorithm=ALGO_CHACHA20)
    
    assert isinstance(result.salt, bytes) and len(result.salt) == 16
    assert isinstance(result.nonce, bytes) and len(result.nonce) == 12
    assert isinstance(result.ciphertext, bytes) and len(result.ciphertext) == len(file_bytes)
    assert isinstance(result.tag, bytes) and len(result.tag) == 16


def test_different_salt_produces_different_key_and_ciphertext():
    """Test 9: Password yang sama pada enkripsi berulang menghasilkan salt, nonce, dan ciphertext berbeda."""
    file_bytes = b"Dokumen yang dienkripsi berulang kali"
    password = "PasswordSamaPersis123!"
    
    res1 = encrypt_file_data(file_bytes=file_bytes, password=password, algorithm=ALGO_AES_GCM)
    res2 = encrypt_file_data(file_bytes=file_bytes, password=password, algorithm=ALGO_AES_GCM)
    
    # Salt unik via CSPRNG
    assert res1.salt != res2.salt
    # Nonce unik via CSPRNG
    assert res1.nonce != res2.nonce
    # Ciphertext berbeda karena salt + nonce berbeda
    assert res1.ciphertext != res2.ciphertext


def test_encryption_verified_with_internal_decrypt_helpers():
    """Test 10: Hasil enkripsi service dapat diverifikasi kembali dengan helper decrypt internal."""
    plaintext = b"Pesan otentik yang diverifikasi integritasnya"
    password = "SecretPasswordSecureDrop!"
    
    # 1. Verifikasi AES-GCM
    res_aes = encrypt_file_data(file_bytes=plaintext, password=password, algorithm=ALGO_AES_GCM)
    key_aes = derive_key(password, res_aes.salt)
    decrypted_aes = decrypt_aes_gcm(
        key=key_aes,
        nonce=res_aes.nonce,
        ciphertext=res_aes.ciphertext,
        tag=res_aes.tag
    )
    assert decrypted_aes == plaintext

    # 2. Verifikasi ChaCha20-Poly1305
    res_chacha = encrypt_file_data(file_bytes=plaintext, password=password, algorithm=ALGO_CHACHA20)
    key_chacha = derive_key(password, res_chacha.salt)
    decrypted_chacha = decrypt_chacha20(
        key=key_chacha,
        nonce=res_chacha.nonce,
        ciphertext=res_chacha.ciphertext,
        tag=res_chacha.tag
    )
    assert decrypted_chacha == plaintext


def test_route_encrypt_post_success(client):
    """Test 11: Endpoint POST /encrypt berhasil memproses upload file dengan parameter valid."""
    data = {
        "file": (io.BytesIO(b"Data file biner untuk route test"), "test_file.txt"),
        "password": "PasswordRouteValid123!",
        "algorithm": "AES-256-GCM"
    }
    
    response = client.post("/encrypt", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    json_data = response.get_json()
    
    assert json_data["success"] is True
    assert json_data["data"]["original_filename"] == "test_file.txt"
    assert json_data["data"]["algorithm"] == "AES-256-GCM"
    assert json_data["data"]["salt_length"] == 16
    assert json_data["data"]["nonce_length"] == 12
    assert json_data["data"]["tag_length"] == 16
    # Pastikan password dan key TIDAK PERNAH ada di response
    assert "password" not in json_data["data"]
    assert "key" not in json_data["data"]


def test_route_encrypt_post_validation_errors(client):
    """Test 12: Endpoint POST /encrypt menangani error validasi (file kosong, password kosong, dsb)."""
    # 1. Tanpa file
    res1 = client.post("/encrypt", data={"password": "pwd", "algorithm": "AES-256-GCM"})
    assert res1.status_code == 400
    assert res1.get_json()["success"] is False

    # 2. File kosong
    res2 = client.post(
        "/encrypt",
        data={"file": (io.BytesIO(b""), "empty.txt"), "password": "pwd", "algorithm": "AES-256-GCM"},
        content_type="multipart/form-data"
    )
    assert res2.status_code == 400
    assert "File tidak boleh kosong" in res2.get_json()["error"]

    # 3. Password kosong
    res3 = client.post(
        "/encrypt",
        data={"file": (io.BytesIO(b"data"), "file.txt"), "password": "", "algorithm": "AES-256-GCM"},
        content_type="multipart/form-data"
    )
    assert res3.status_code == 400
    assert "Password wajib diisi" in res3.get_json()["error"]

    # 4. Algoritma tidak valid
    res4 = client.post(
        "/encrypt",
        data={"file": (io.BytesIO(b"data"), "file.txt"), "password": "pwd", "algorithm": "DES-ECB"},
        content_type="multipart/form-data"
    )
    assert res4.status_code == 400
    assert "Algoritma tidak valid" in res4.get_json()["error"]
