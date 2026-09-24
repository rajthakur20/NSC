"""
Unit tests for AES-256-GCM authenticated encryption and PBKDF2 key derivation.
"""

import pytest
from backend.crypto import (
    CryptoError,
    decrypt_file_data,
    derive_key,
    encrypt_file_data,
)
from backend.config import PBKDF2_SALT_BYTES, GENERIC_DECRYPTION_ERROR


def test_derive_key_length_and_determinism():
    salt = b"\x01" * PBKDF2_SALT_BYTES
    password = "SuperSecretPassword123!"
    key1 = derive_key(password, salt, iterations=1000)
    key2 = derive_key(password, salt, iterations=1000)
    
    assert len(key1) == 32  # 256 bits
    assert key1 == key2


def test_derive_key_different_salts():
    password = "SuperSecretPassword123!"
    salt1 = b"\x01" * PBKDF2_SALT_BYTES
    salt2 = b"\x02" * PBKDF2_SALT_BYTES
    
    key1 = derive_key(password, salt1, iterations=1000)
    key2 = derive_key(password, salt2, iterations=1000)
    assert key1 != key2


def test_encrypt_decrypt_round_trip():
    original_data = b"Sensitive Network Security Lab Report Contents - Student ID 101"
    filename = "lab_report.pdf"
    password = "ComplexPassword#2026"
    
    # Encrypt
    enc_result = encrypt_file_data(original_data, filename, password, iterations=1000)
    assert enc_result.encrypted_package.startswith(b"SFE1")
    assert enc_result.original_filename == filename
    assert enc_result.algorithm == "AES-256-GCM"
    
    # Decrypt with correct password
    dec_result = decrypt_file_data(enc_result.encrypted_package, password, iterations=1000)
    assert dec_result.decrypted_data == original_data
    assert dec_result.original_filename == filename
    assert dec_result.original_hash == enc_result.original_hash
    assert dec_result.authenticated is True


def test_nonce_freshness_and_semantic_security():
    # Encrypting the exact same plaintext with the same password twice MUST yield different ciphertexts
    data = b"Identical Payload"
    password = "SamePassword123"
    
    res1 = encrypt_file_data(data, "file.txt", password, iterations=1000)
    res2 = encrypt_file_data(data, "file.txt", password, iterations=1000)
    
    assert res1.nonce_hex != res2.nonce_hex
    assert res1.salt_hex != res2.salt_hex
    assert res1.encrypted_package != res2.encrypted_package


def test_wrong_password_rejection():
    original_data = b"Top Secret Payload"
    password = "CorrectPassword123"
    wrong_password = "WrongPassword999"
    
    enc_result = encrypt_file_data(original_data, "secret.txt", password, iterations=1000)
    
    with pytest.raises(CryptoError) as exc_info:
        decrypt_file_data(enc_result.encrypted_package, wrong_password, iterations=1000)
    
    assert str(exc_info.value) == GENERIC_DECRYPTION_ERROR


def test_tampered_ciphertext_rejection():
    original_data = b"Unmodified Authentic Transaction Data"
    password = "ValidPassword123"
    
    enc_result = encrypt_file_data(original_data, "tx.dat", password, iterations=1000)
    package = bytearray(enc_result.encrypted_package)
    
    # Tamper with the last byte (part of ciphertext or authentication tag)
    package[-1] ^= 0xFF
    
    with pytest.raises(CryptoError) as exc_info:
        decrypt_file_data(bytes(package), password, iterations=1000)
    
    assert str(exc_info.value) == GENERIC_DECRYPTION_ERROR


def test_tampered_header_metadata_rejection():
    # Because the header is passed as Additional Authenticated Data (AAD) to AES-GCM,
    # modifying any header byte (e.g. filename, salt, nonce, hash) MUST fail authentication!
    original_data = b"Confidential Metadata"
    password = "ValidPassword123"
    
    enc_result = encrypt_file_data(original_data, "document.docx", password, iterations=1000)
    package = bytearray(enc_result.encrypted_package)
    
    # Modify a byte in the salt (bytes 4 to 20)
    package[10] ^= 0x01
    
    with pytest.raises(CryptoError) as exc_info:
        decrypt_file_data(bytes(package), password, iterations=1000)
    
    assert str(exc_info.value) == GENERIC_DECRYPTION_ERROR


def test_invalid_magic_header():
    package = b"INVALID_HEADER_DATA_12345678901234567890123456789012345678901234567890"
    with pytest.raises(CryptoError) as exc_info:
        decrypt_file_data(package, "password123")
    assert str(exc_info.value) == GENERIC_DECRYPTION_ERROR


def test_truncated_package():
    short_package = b"SFE1" + b"\x00" * 10
    with pytest.raises(CryptoError) as exc_info:
        decrypt_file_data(short_package, "password123")
    assert str(exc_info.value) == GENERIC_DECRYPTION_ERROR


def test_empty_file_encryption():
    empty_data = b""
    password = "PasswordForEmptyFile"
    enc_result = encrypt_file_data(empty_data, "empty.txt", password, iterations=1000)
    dec_result = decrypt_file_data(enc_result.encrypted_package, password, iterations=1000)
    assert dec_result.decrypted_data == b""
    assert dec_result.original_filename == "empty.txt"
