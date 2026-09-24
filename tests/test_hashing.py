"""
Unit tests for SHA-256 hashing and constant-time integrity verification.
"""

import io
import pytest
from backend.hashing import (
    calculate_sha256,
    calculate_sha256_stream,
    compare_hashes,
    verify_file_integrity,
)


def test_calculate_sha256_known_vector():
    # Known SHA-256 test vector for empty string:
    # e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert calculate_sha256(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    
    # Known SHA-256 test vector for "abc":
    # ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    assert calculate_sha256(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_calculate_sha256_invalid_type():
    with pytest.raises(TypeError):
        calculate_sha256("not-bytes")  # type: ignore


def test_calculate_sha256_stream():
    content = b"Streamed content for cryptographic integrity testing."
    stream = io.BytesIO(content)
    stream_hash = calculate_sha256_stream(stream, chunk_size=8)
    direct_hash = calculate_sha256(content)
    assert stream_hash == direct_hash


def test_compare_hashes_matching():
    h1 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    h2 = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
    assert compare_hashes(h1, h2) is True


def test_compare_hashes_different():
    h1 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    h2 = "ca7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ae"
    assert compare_hashes(h1, h2) is False


def test_compare_hashes_invalid_inputs():
    assert compare_hashes(None, "abc") is False  # type: ignore
    assert compare_hashes("abc", 123) is False   # type: ignore


def test_verify_file_integrity_success():
    data = b"Final Year Engineering Project Data - Confidential"
    ref_hash = calculate_sha256(data)
    is_valid, current_hash = verify_file_integrity(data, ref_hash)
    assert is_valid is True
    assert current_hash == ref_hash


def test_verify_file_integrity_failure():
    data = b"Original Text"
    tampered_data = b"Modified Text"
    ref_hash = calculate_sha256(data)
    is_valid, current_hash = verify_file_integrity(tampered_data, ref_hash)
    assert is_valid is False
    assert current_hash != ref_hash
