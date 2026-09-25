import base64
import json

import pytest
import io

from app import create_app

from services.encryption_service import ALGO_AES_GCM, ALGO_CHACHA20, encrypt_file_data
from services.sdrop_service import (
    AuthenticationError,
    SdropFormatError,
    create_hybrid_sdrop,
    decrypt_hybrid_sdrop,
    decrypt_sdrop,
    generate_rsa_key_pair,
    package_encryption_result,
    read_sdrop,
)


@pytest.mark.parametrize("algorithm", [ALGO_AES_GCM, ALGO_CHACHA20])
def test_password_sdrop_round_trip(algorithm):
    result = encrypt_file_data(b"file O2 yang harus tetap biner", "password-uji", algorithm, "laporan.bin")
    payload = package_encryption_result(result)
    parsed = read_sdrop(payload)

    assert parsed.algorithm == algorithm
    assert parsed.original_filename == "laporan.bin"
    plaintext, filename = decrypt_sdrop(payload, "password-uji")
    assert plaintext == b"file O2 yang harus tetap biner"
    assert filename == "laporan.bin"


def test_wrong_password_is_rejected():
    payload = package_encryption_result(encrypt_file_data(b"rahasia", "password-benar"))
    with pytest.raises(AuthenticationError, match="Authentication Failed"):
        decrypt_sdrop(payload, "password-salah")


def test_modified_ciphertext_is_rejected():
    payload = package_encryption_result(encrypt_file_data(b"rahasia", "password-benar"))
    document = json.loads(payload)
    ciphertext = bytearray(base64.b64decode(document["ciphertext"]))
    ciphertext[0] ^= 1
    document["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")

    with pytest.raises(AuthenticationError, match="Authentication Failed"):
        decrypt_sdrop(json.dumps(document).encode(), "password-benar")


def test_corrupt_sdrop_is_rejected():
    with pytest.raises(SdropFormatError):
        read_sdrop(b"not-a-sdrop")


def test_hybrid_rsa_oaep_round_trip_and_wrong_key_rejection():
    private_key, public_key = generate_rsa_key_pair()
    payload = create_hybrid_sdrop(b"hybrid secret", public_key, original_filename="hybrid.txt")
    plaintext, filename = decrypt_hybrid_sdrop(payload, private_key)
    assert plaintext == b"hybrid secret"
    assert filename == "hybrid.txt"

    other_private, _ = generate_rsa_key_pair()
    with pytest.raises(AuthenticationError, match="Authentication Failed"):
        decrypt_hybrid_sdrop(payload, other_private)


def test_encrypt_and_decrypt_routes_exchange_sdrop():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        encrypted = client.post(
            "/encrypt",
            data={
                "file": (io.BytesIO(b"route integration"), "route.txt"),
                "password": "route-password",
                "algorithm": ALGO_AES_GCM,
            },
            content_type="multipart/form-data",
        )
        assert encrypted.status_code == 200
        package = base64.b64decode(encrypted.get_json()["data"]["sdrop_base64"])
        decrypted = client.post(
            "/decrypt",
            data={"file": (io.BytesIO(package), "route.txt.sdrop"), "password": "route-password"},
            content_type="multipart/form-data",
        )
        body = decrypted.get_json()
        assert decrypted.status_code == 200
        assert body["success"] is True
        assert base64.b64decode(body["data"]["file_base64"]) == b"route integration"
