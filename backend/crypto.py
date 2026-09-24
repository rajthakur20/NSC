"""
Cryptographic Operations Module for Secure File Integrity & Encryption Tool.
Implements AES-256-GCM authenticated encryption and PBKDF2-HMAC-SHA256 key derivation.
"""

import hmac
import os
import secrets
import struct
from typing import NamedTuple, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .config import (
    AES_KEY_BYTES,
    GCM_NONCE_BYTES,
    GCM_TAG_BYTES,
    GENERIC_DECRYPTION_ERROR,
    MAGIC_HEADER,
    PBKDF2_ITERATIONS,
    PBKDF2_SALT_BYTES,
)
from .hashing import calculate_sha256, compare_hashes


class CryptoError(Exception):
    """Generic cryptographic operation exception."""
    pass


class EncryptionResult(NamedTuple):
    encrypted_package: bytes
    original_hash: str
    original_filename: str
    salt_hex: str
    nonce_hex: str
    algorithm: str
    kdf: str


class DecryptionResult(NamedTuple):
    decrypted_data: bytes
    original_filename: str
    original_hash: str
    algorithm: str
    authenticated: bool


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derive a 256-bit symmetric encryption key from a user password and salt
    using PBKDF2-HMAC-SHA256.
    
    Args:
        password (str): User supplied passphrase.
        salt (bytes): Cryptographically random salt.
        iterations (int): Work factor (iteration count).
        
    Returns:
        bytes: 32-byte (256-bit) AES key.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    if not isinstance(salt, bytes) or len(salt) != PBKDF2_SALT_BYTES:
        raise ValueError(f"Salt must be {PBKDF2_SALT_BYTES} bytes.")
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file_data(
    file_bytes: bytes,
    filename: str,
    password: str,
    iterations: int = PBKDF2_ITERATIONS,
) -> EncryptionResult:
    """
    Encrypt file data using AES-256-GCM and bundle it into a secure container format (.sfe).
    
    Process:
    1. Compute SHA-256 hash of original file bytes.
    2. Generate cryptographically secure random 16-byte salt.
    3. Derive 256-bit AES key via PBKDF2-HMAC-SHA256.
    4. Generate fresh random 12-byte nonce (96 bits).
    5. Construct container header and bind it as Additional Authenticated Data (AAD).
    6. Encrypt plaintext using AES-256-GCM.
    7. Pack header + ciphertext + authentication tag into .sfe package.
    
    Args:
        file_bytes (bytes): Plaintext file contents.
        filename (str): Sanitized original filename.
        password (str): User password for key derivation.
        iterations (int): PBKDF2 iterations.
        
    Returns:
        EncryptionResult: Named tuple with package bytes and operation metadata.
    """
    if not isinstance(file_bytes, (bytes, bytearray)):
        raise TypeError("file_bytes must be bytes or bytearray.")
    if not password:
        raise ValueError("Password cannot be empty.")
    
    # 1. Compute original SHA-256 hash
    orig_hash_hex = calculate_sha256(file_bytes)
    orig_hash_bytes = bytes.fromhex(orig_hash_hex)  # 32 bytes
    
    # 2. Generate random salt and derive key
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    derived_key = derive_key(password, salt, iterations)
    
    # 3. Generate fresh random 96-bit nonce
    nonce = secrets.token_bytes(GCM_NONCE_BYTES)
    
    # 4. Encode filename safely
    filename_clean = os.path.basename(filename) or "unnamed_file"
    filename_bytes = filename_clean.encode("utf-8")
    if len(filename_bytes) > 65535:
        raise ValueError("Filename is too long.")
    
    # 5. Build Container Header:
    # [MAGIC(4)] + [SALT(16)] + [NONCE(12)] + [HASH(32)] + [FILENAME_LEN(2)] + [FILENAME(N)]
    header = (
        MAGIC_HEADER +
        salt +
        nonce +
        orig_hash_bytes +
        struct.pack(">H", len(filename_bytes)) +
        filename_bytes
    )
    
    # 6. Encrypt with AES-256-GCM using Header as Additional Authenticated Data (AAD)
    # This ensures any tampering with salt, nonce, filename or hash triggers authentication failure
    aesgcm = AESGCM(derived_key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, file_bytes, associated_data=header)
    
    # 7. Final Package = Header + Ciphertext + Tag
    encrypted_package = header + ciphertext_and_tag
    
    return EncryptionResult(
        encrypted_package=encrypted_package,
        original_hash=orig_hash_hex,
        original_filename=filename_clean,
        salt_hex=salt.hex(),
        nonce_hex=nonce.hex(),
        algorithm="AES-256-GCM",
        kdf="PBKDF2-HMAC-SHA256",
    )


def decrypt_file_data(
    package_bytes: bytes,
    password: str,
    iterations: int = PBKDF2_ITERATIONS,
) -> DecryptionResult:
    """
    Decrypt an .sfe encrypted container package and verify authenticity and integrity.
    
    Process:
    1. Validate container length and magic header.
    2. Extract salt, nonce, original SHA-256 hash, and original filename.
    3. Reconstruct header for AAD verification.
    4. Derive AES key using PBKDF2-HMAC-SHA256 from password + salt.
    5. Perform AES-256-GCM authenticated decryption.
    6. Verify SHA-256 integrity of the recovered plaintext.
    
    Args:
        package_bytes (bytes): The full .sfe package.
        password (str): The user provided password.
        iterations (int): PBKDF2 iteration count.
        
    Returns:
        DecryptionResult: Named tuple with decrypted bytes and metadata.
        
    Raises:
        CryptoError: If password is wrong, package is tampered, or container is corrupt.
    """
    if not isinstance(package_bytes, (bytes, bytearray)):
        raise CryptoError(GENERIC_DECRYPTION_ERROR)
    if not password:
        raise CryptoError(GENERIC_DECRYPTION_ERROR)
    
    # Minimum valid header size:
    # 4 (Magic) + 16 (Salt) + 12 (Nonce) + 32 (Hash) + 2 (NameLen) = 66 bytes
    # Plus at least GCM_TAG_BYTES (16) = 82 bytes total
    min_size = len(MAGIC_HEADER) + PBKDF2_SALT_BYTES + GCM_NONCE_BYTES + 32 + 2 + GCM_TAG_BYTES
    if len(package_bytes) < min_size:
        raise CryptoError(GENERIC_DECRYPTION_ERROR)
    
    offset = 0
    # 1. Verify Magic Header
    magic = package_bytes[offset : offset + len(MAGIC_HEADER)]
    offset += len(MAGIC_HEADER)
    if magic != MAGIC_HEADER:
        raise CryptoError(GENERIC_DECRYPTION_ERROR)
    
    # 2. Extract Salt
    salt = package_bytes[offset : offset + PBKDF2_SALT_BYTES]
    offset += PBKDF2_SALT_BYTES
    
    # 3. Extract Nonce
    nonce = package_bytes[offset : offset + GCM_NONCE_BYTES]
    offset += GCM_NONCE_BYTES
    
    # 4. Extract Original SHA-256 hash bytes
    orig_hash_bytes = package_bytes[offset : offset + 32]
    orig_hash_hex = orig_hash_bytes.hex().lower()
    offset += 32
    
    # 5. Extract Filename Length and Filename
    filename_len = struct.unpack(">H", package_bytes[offset : offset + 2])[0]
    offset += 2
    
    if len(package_bytes) < offset + filename_len + GCM_TAG_BYTES:
        raise CryptoError(GENERIC_DECRYPTION_ERROR)
    
    filename_bytes = package_bytes[offset : offset + filename_len]
    offset += filename_len
    
    try:
        filename = filename_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise CryptoError(GENERIC_DECRYPTION_ERROR)
    
    # 6. Reconstruct header for AAD verification
    header = package_bytes[:offset]
    ciphertext_and_tag = package_bytes[offset:]
    
    # 7. Derive key from password and extracted salt
    try:
        derived_key = derive_key(password, salt, iterations)
    except Exception:
        raise CryptoError(GENERIC_DECRYPTION_ERROR)
    
    # 8. Decrypt with AES-256-GCM and verify AAD + Tag
    try:
        aesgcm = AESGCM(derived_key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data=header)
    except (InvalidTag, Exception):
        # Generic error message avoids oracle and distinguishes neither wrong pass nor tampering
        raise CryptoError(GENERIC_DECRYPTION_ERROR)
    
    # 9. Verify internal SHA-256 hash
    actual_hash_hex = calculate_sha256(decrypted_data)
    if not compare_hashes(actual_hash_hex, orig_hash_hex):
        raise CryptoError(GENERIC_DECRYPTION_ERROR)
    
    return DecryptionResult(
        decrypted_data=decrypted_data,
        original_filename=filename,
        original_hash=orig_hash_hex,
        algorithm="AES-256-GCM",
        authenticated=True,
    )
