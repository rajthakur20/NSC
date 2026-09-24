"""
Comprehensive API test suite for Flask endpoints.
Tests encryption, decryption, native HTTP file downloads, hashing, and integrity verification.
"""

import io
import pytest
from backend.app import create_app
from backend.config import GENERIC_DECRYPTION_ERROR


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert "AES-256-GCM" in data["ciphers"]
    assert data["hash"] == "SHA-256"


def test_api_encrypt_direct_attachment_response(client):
    file_content = b"Confidential Research Paper Data 2026"
    filename = "EXP2(RAJ THAKUR , ROLL NO 59).pdf"
    password = "StrongPassword!2026"

    # POST /api/encrypt -> Direct binary download response
    enc_resp = client.post(
        "/api/encrypt",
        data={"file": (io.BytesIO(file_content), filename), "password": password},
        content_type="multipart/form-data"
    )
    assert enc_resp.status_code == 200
    assert enc_resp.content_type == "application/octet-stream"
    assert enc_resp.data[:4] == b"SFE1"

    # Verify custom headers
    assert enc_resp.headers["X-Original-Filename"] == filename
    assert enc_resp.headers["X-Encrypted-Filename"] == f"{filename}.sfe"
    assert enc_resp.headers["X-Algorithm"] == "AES-256-GCM"
    assert enc_resp.headers["X-KDF"] == "PBKDF2-HMAC-SHA256"
    assert len(enc_resp.headers["X-Original-Hash"]) == 64

    # Verify Content-Disposition contains exact user filename
    disp = enc_resp.headers["Content-Disposition"]
    assert f'filename="{filename}.sfe"' in disp


def test_api_encrypt_missing_password(client):
    data = {
        "file": (io.BytesIO(b"data"), "sample.txt"),
        "password": "",
    }
    response = client.post("/api/encrypt", data=data, content_type="multipart/form-data")
    assert response.status_code == 400
    res_data = response.get_json()
    assert res_data["success"] is False
    assert "Password cannot be empty" in res_data["error"]


def test_api_encrypt_missing_file(client):
    data = {
        "password": "Password123",
    }
    response = client.post("/api/encrypt", data=data, content_type="multipart/form-data")
    assert response.status_code == 400
    res_data = response.get_json()
    assert res_data["success"] is False


def test_api_encrypt_path_traversal_filename(client):
    data = {
        "file": (io.BytesIO(b"secure data"), "../../../etc/passwd"),
        "password": "Password123",
    }
    response = client.post("/api/encrypt", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert response.headers["X-Original-Filename"] == "passwd"
    assert response.headers["X-Encrypted-Filename"] == "passwd.sfe"
    assert 'filename="passwd.sfe"' in response.headers["Content-Disposition"]


def test_api_full_encrypt_decrypt_round_trip(client):
    original_text = b"%PDF-1.4\n1 0 obj\n<< /Title (Lab Submission) >>\nendobj\n" * 20
    filename = "EXP2(RAJ THAKUR , ROLL NO 59).pdf"
    password = "MasterKey@Pass123"

    # 1. Encrypt -> returns binary SFE directly
    enc_resp = client.post(
        "/api/encrypt",
        data={"file": (io.BytesIO(original_text), filename), "password": password},
        content_type="multipart/form-data"
    )
    assert enc_resp.status_code == 200
    assert enc_resp.content_type == "application/octet-stream"
    sfe_bytes = enc_resp.data
    orig_hash = enc_resp.headers["X-Original-Hash"]
    assert 'filename="EXP2(RAJ THAKUR , ROLL NO 59).pdf.sfe"' in enc_resp.headers["Content-Disposition"]

    # 2. Decrypt with correct password -> returns binary original PDF directly
    dec_resp = client.post(
        "/api/decrypt",
        data={"file": (io.BytesIO(sfe_bytes), f"{filename}.sfe"), "password": password},
        content_type="multipart/form-data"
    )
    assert dec_resp.status_code == 200
    assert dec_resp.content_type == "application/octet-stream"
    assert dec_resp.data == original_text
    assert dec_resp.headers["X-Original-Filename"] == filename
    assert dec_resp.headers["X-Authenticated"] == "True"
    assert dec_resp.headers["X-Original-Hash"] == orig_hash
    assert 'filename="EXP2(RAJ THAKUR , ROLL NO 59).pdf"' in dec_resp.headers["Content-Disposition"]


def test_api_decrypt_wrong_password(client):
    original_text = b"Top secret contents"
    password = "CorrectPassword123"

    enc_resp = client.post(
        "/api/encrypt",
        data={"file": (io.BytesIO(original_text), "secret.txt"), "password": password},
        content_type="multipart/form-data"
    )
    sfe_bytes = enc_resp.data

    dec_resp = client.post(
        "/api/decrypt",
        data={"file": (io.BytesIO(sfe_bytes), "secret.txt.sfe"), "password": "WrongPassword999"},
        content_type="multipart/form-data"
    )
    assert dec_resp.status_code == 400
    dec_json = dec_resp.get_json()
    assert dec_json["success"] is False
    assert dec_json["error"] == GENERIC_DECRYPTION_ERROR


def test_api_decrypt_tampered_payload(client):
    original_text = b"Sensitive Financial Ledger"
    password = "CorrectPassword123"

    enc_resp = client.post(
        "/api/encrypt",
        data={"file": (io.BytesIO(original_text), "ledger.csv"), "password": password},
        content_type="multipart/form-data"
    )
    sfe_bytes = bytearray(enc_resp.data)
    sfe_bytes[-5] ^= 0xAA  # Tamper with GCM tag

    dec_resp = client.post(
        "/api/decrypt",
        data={"file": (io.BytesIO(bytes(sfe_bytes)), "ledger.csv.sfe"), "password": password},
        content_type="multipart/form-data"
    )
    assert dec_resp.status_code == 400
    dec_json = dec_resp.get_json()
    assert dec_json["success"] is False
    assert dec_json["error"] == GENERIC_DECRYPTION_ERROR


def test_api_download_file_nonexistent(client):
    resp = client.get("/api/download/file/nonexistent-file-12345.sfe")
    assert resp.status_code == 404


def test_api_hash_endpoint(client):
    sample_data = b"Hello, SHA-256 Cryptographic Hashing!"
    resp = client.post(
        "/api/hash",
        data={"file": (io.BytesIO(sample_data), "hello.txt")},
        content_type="multipart/form-data"
    )
    assert resp.status_code == 200
    res_data = resp.get_json()
    assert res_data["success"] is True
    assert res_data["algorithm"] == "SHA-256"
    assert len(res_data["sha256"]) == 64
    assert res_data["filename"] == "hello.txt"
    assert res_data["size"] == len(sample_data)


def test_api_verify_matching_hash(client):
    sample_data = b"Authentic Verification Payload"
    h_resp = client.post(
        "/api/hash",
        data={"file": (io.BytesIO(sample_data), "verify.txt")},
        content_type="multipart/form-data"
    )
    ref_hash = h_resp.get_json()["sha256"]

    v_resp = client.post(
        "/api/verify",
        data={
            "file": (io.BytesIO(sample_data), "verify.txt"),
            "reference_hash": ref_hash,
        },
        content_type="multipart/form-data"
    )
    assert v_resp.status_code == 200
    v_json = v_resp.get_json()
    assert v_json["success"] is True
    assert v_json["verified"] is True
    assert v_json["status"] == "Verified"


def test_api_verify_modified_file_hash_mismatch(client):
    original_data = b"Original Authentic Content"
    tampered_data = b"Modified Tampered Content"

    h_resp = client.post(
        "/api/hash",
        data={"file": (io.BytesIO(original_data), "doc.txt")},
        content_type="multipart/form-data"
    )
    ref_hash = h_resp.get_json()["sha256"]

    v_resp = client.post(
        "/api/verify",
        data={
            "file": (io.BytesIO(tampered_data), "doc.txt"),
            "reference_hash": ref_hash,
        },
        content_type="multipart/form-data"
    )
    assert v_resp.status_code == 200
    v_json = v_resp.get_json()
    assert v_json["success"] is True
    assert v_json["verified"] is False
    assert v_json["status"] == "Integrity Check Failed"
    assert v_json["current_hash"] != ref_hash


def test_api_verify_missing_reference_hash(client):
    sample_data = b"Data"
    v_resp = client.post(
        "/api/verify",
        data={"file": (io.BytesIO(sample_data), "doc.txt")},
        content_type="multipart/form-data"
    )
    assert v_resp.status_code == 400
    v_json = v_resp.get_json()
    assert v_json["success"] is False
    assert "Reference SHA-256 hash is required" in v_json["error"]
