"""
Secure File Hashing and Integrity Verification Module.
Implements SHA-256 cryptographic hashing and constant-time integrity comparison.
"""

import hashlib
import hmac
from typing import BinaryIO, Union


def calculate_sha256(data: bytes) -> str:
    """
    Calculate the SHA-256 cryptographic hash of a given byte string.
    
    Args:
        data (bytes): Input byte array.
        
    Returns:
        str: 64-character lowercase hexadecimal SHA-256 digest.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be bytes or bytearray")
    
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest().lower()


def calculate_sha256_stream(stream: BinaryIO, chunk_size: int = 65536) -> str:
    """
    Calculate SHA-256 digest for an open binary file/stream in chunks to conserve memory.
    
    Args:
        stream (BinaryIO): File-like binary stream.
        chunk_size (int): Size of chunks to read at a time (default: 64 KB).
        
    Returns:
        str: 64-character lowercase hexadecimal SHA-256 digest.
    """
    hasher = hashlib.sha256()
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
    return hasher.hexdigest().lower()


def compare_hashes(hash1: str, hash2: str) -> bool:
    """
    Compare two SHA-256 hash strings using constant-time comparison
    to mitigate side-channel timing attacks.
    
    Args:
        hash1 (str): First hash string.
        hash2 (str): Second hash string.
        
    Returns:
        bool: True if hashes are identical (case-insensitive), False otherwise.
    """
    if not isinstance(hash1, str) or not isinstance(hash2, str):
        return False
    
    h1 = hash1.strip().lower().encode("utf-8")
    h2 = hash2.strip().lower().encode("utf-8")
    
    return hmac.compare_digest(h1, h2)


def verify_file_integrity(file_bytes: bytes, reference_hash: str) -> tuple[bool, str]:
    """
    Compute SHA-256 of file_bytes and verify against a reference hash.
    
    Args:
        file_bytes (bytes): Raw file content.
        reference_hash (str): Expected reference SHA-256 hash.
        
    Returns:
        tuple[bool, str]: (is_verified, calculated_sha256_hash)
    """
    current_hash = calculate_sha256(file_bytes)
    is_valid = compare_hashes(current_hash, reference_hash)
    return is_valid, current_hash
