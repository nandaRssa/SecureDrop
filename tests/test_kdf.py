"""
Unit test suite untuk modul KDF (Key Derivation Function) PBKDF2-HMAC-SHA256.
"""

import pytest
from crypto.kdf import (
    generate_salt,
    derive_key,
    SALT_LENGTH,
    KEY_LENGTH,
    PBKDF2_ITERATIONS,
)


def test_salt_length():
    """Test 1: Salt yang dihasilkan memiliki panjang tepat 16 byte (128 bit)."""
    salt = generate_salt()
    assert isinstance(salt, bytes)
    assert len(salt) == SALT_LENGTH
    assert len(salt) == 16


def test_derived_key_length():
    """Test 2: Derived key yang dihasilkan memiliki panjang tepat 32 byte (256 bit)."""
    salt = generate_salt()
    key = derive_key(password="RahasiaUser123!", salt=salt, iterations=100_000)
    assert isinstance(key, bytes)
    assert len(key) == KEY_LENGTH
    assert len(key) == 32


def test_deterministic_key_derivation():
    """Test 3: Password dan salt yang identik menghasilkan derived key yang sama persis."""
    salt = generate_salt()
    password = "TestPassword_Deterministic"
    
    key1 = derive_key(password=password, salt=salt, iterations=100_000)
    key2 = derive_key(password=password, salt=salt, iterations=100_000)
    
    assert key1 == key2


def test_different_salt_produces_different_key():
    """Test 4: Password yang sama dengan salt berbeda menghasilkan derived key yang berbeda."""
    password = "SamePasswordString"
    salt1 = generate_salt()
    salt2 = generate_salt()
    
    assert salt1 != salt2  # Memastikan randomness salt
    
    key1 = derive_key(password=password, salt=salt1, iterations=100_000)
    key2 = derive_key(password=password, salt=salt2, iterations=100_000)
    
    assert key1 != key2


def test_different_password_produces_different_key():
    """Test 5: Password berbeda dengan salt yang sama menghasilkan derived key yang berbeda."""
    salt = generate_salt()
    password1 = "PasswordAlpha"
    password2 = "PasswordBeta"
    
    key1 = derive_key(password=password1, salt=salt, iterations=100_000)
    key2 = derive_key(password=password2, salt=salt, iterations=100_000)
    
    assert key1 != key2


def test_invalid_salt_rejected():
    """Test 6: Salt yang tidak valid (kurang dari 16 byte / tipe salah) ditolak dengan exception."""
    password = "ValidPassword123"
    
    # Salt terlalu pendek
    with pytest.raises(ValueError, match="minimal 16 byte"):
        derive_key(password=password, salt=b"short_salt")
        
    # Salt bukan bytes (misal string)
    with pytest.raises(TypeError, match="bertipe bytes"):
        derive_key(password=password, salt="string_salt_invalid")  # type: ignore


def test_invalid_password_rejected():
    """Test 7: Password kosong atau bertipe salah ditolak dengan exception yang aman."""
    salt = generate_salt()
    
    # Password string kosong
    with pytest.raises(ValueError, match="Password tidak boleh kosong"):
        derive_key(password="", salt=salt)
        
    # Password None
    with pytest.raises(TypeError, match="Password tidak boleh bernilai None"):
        derive_key(password=None, salt=salt)  # type: ignore

    # Password bertipe salah (misal integer/list)
    with pytest.raises(TypeError, match="Password harus berupa string atau bytes"):
        derive_key(password=123456, salt=salt)  # type: ignore


def test_default_constants():
    """Test 8: Memastikan nilai default konstanta PBKDF2 memenuhi standar keamanan."""
    assert SALT_LENGTH == 16
    assert KEY_LENGTH == 32
    assert PBKDF2_ITERATIONS >= 100_000
