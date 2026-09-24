"""
Unit tests untuk inisialisasi aplikasi Flask dan routing antarmuka SecureDrop.
"""

import pytest
from app import create_app


@pytest.fixture
def client():
    """Fixture untuk inisialisasi Flask test client."""
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_redirect_to_encrypt(client):
    """Test 1: Route '/' harus mengarahkan (redirect) ke '/encrypt'."""
    response = client.get("/")
    assert response.status_code == 302
    assert response.headers["Location"] == "/encrypt"


def test_encrypt_page_loads(client):
    """Test 2: Halaman Encrypt & Send '/encrypt' harus merespons status 200."""
    response = client.get("/encrypt")
    assert response.status_code == 200
    assert b"Encrypt &amp; Send" in response.data or b"Encrypt & Send" in response.data
    assert b"AES-256-GCM" in response.data
    assert b"ChaCha20-Poly1305" in response.data


def test_decrypt_placeholder_page_loads(client):
    """Test 3: Halaman Receive & Decrypt '/decrypt' harus merespons status 200."""
    response = client.get("/decrypt")
    assert response.status_code == 200
    assert b"Receive &amp; Decrypt" in response.data or b"Receive & Decrypt" in response.data
    assert b"Modul Orang 2" in response.data


def test_testing_placeholder_page_loads(client):
    """Test 4: Halaman Security Testing '/testing' harus merespons status 200."""
    response = client.get("/testing")
    assert response.status_code == 200
    assert b"Security Testing" in response.data
    assert b"Modul Orang 3" in response.data


def test_navigation_active_class(client):
    """Test 5: Memastikan menu navigasi aktif sesuai halaman yang diakses."""
    response_encrypt = client.get("/encrypt")
    assert b'class="nav-link active"' in response_encrypt.data
