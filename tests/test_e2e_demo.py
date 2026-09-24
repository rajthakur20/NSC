"""
End-to-End System Demonstration and Cryptographic Verification Script.
Tests the complete workflow with user filename:
EXP2(RAJ THAKUR , ROLL NO 59).pdf -> Encrypt -> Download .sfe -> Decrypt -> Download original
Verifies byte-for-byte fidelity and SHA-256 hash match.
"""

import io
import sys
from pathlib import Path

if sys.platform.startswith("win"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app import create_app
from backend.crypto import encrypt_file_data, decrypt_file_data, CryptoError
from backend.hashing import calculate_sha256, verify_file_integrity


def run_full_demonstration():
    print("=" * 70)
    print("SECURE FILE INTEGRITY & ENCRYPTION TOOL - FULL SYSTEM VERIFICATION")
    print("=" * 70)

    sample_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Title (Network Security Lab Experiment 2) >>\nendobj\n"
        b"CONFIDENTIAL NETWORK SECURITY AND CRYPTOGRAPHY LAB REPORT\n"
        b"Student: Raj Thakur, Roll No 59\n"
        b"Topic: Authenticated Encryption with AES-256-GCM & PBKDF2-HMAC-SHA256\n"
        b"Date: 2026-09-25\n"
        b"Data: File integrity verification via SHA-256 with constant-time equality."
    )
    original_filename = "EXP2(RAJ THAKUR , ROLL NO 59).pdf"
    correct_password = "SecureCollegePassword#2026!"
    wrong_password = "IncorrectPassword999"

    print("\n[Step 1] Original File Details:")
    print(f"  Filename: {original_filename}")
    print(f"  Size: {len(sample_content)} bytes")
    orig_hash = calculate_sha256(sample_content)
    print(f"  SHA-256 Hash: {orig_hash}")

    # 2. Encrypt
    print("\n[Step 2] Executing AES-256-GCM Encryption with PBKDF2 Key Derivation...")
    enc_result = encrypt_file_data(
        file_bytes=sample_content,
        filename=original_filename,
        password=correct_password,
    )
    sfe_package = enc_result.encrypted_package
    print("  [PASS] Encryption Success!")
    print(f"  Container Magic: {sfe_package[:4]}")
    print(f"  Salt (16 bytes): {enc_result.salt_hex}")
    print(f"  Nonce (12 bytes): {enc_result.nonce_hex}")
    print(f"  Package Size: {len(sfe_package)} bytes")

    # 3. Decrypt with correct password
    print("\n[Step 3] Decrypting with CORRECT password...")
    dec_result = decrypt_file_data(package_bytes=sfe_package, password=correct_password)
    print("  [PASS] Decryption Success!")
    print(f"  Recovered Filename: {dec_result.original_filename}")
    print(f"  Authenticated: {dec_result.authenticated}")
    print(f"  SHA-256: {dec_result.original_hash}")

    # 4. Byte-for-byte match
    print("\n[Step 4] Verifying byte-for-byte parity...")
    assert dec_result.decrypted_data == sample_content, "FAIL: bytes mismatch!"
    assert dec_result.original_filename == original_filename, "FAIL: filename mismatch!"
    assert dec_result.original_hash == orig_hash, "FAIL: hash mismatch!"
    print("  [PASS] Recovered file is 100% IDENTICAL to original!")

    # 5. Wrong password
    print("\n[Step 5] Decrypting with WRONG password...")
    try:
        decrypt_file_data(package_bytes=sfe_package, password=wrong_password)
        print("  [FAIL] Should have been rejected!")
        sys.exit(1)
    except CryptoError as e:
        print(f"  [PASS] Correctly rejected with generic message: \"{e}\"")

    # 6. Tampered package
    print("\n[Step 6] Tampering with encrypted package (flip authentication tag byte)...")
    tampered = bytearray(sfe_package)
    tampered[-1] ^= 0xFF
    try:
        decrypt_file_data(package_bytes=bytes(tampered), password=correct_password)
        print("  [FAIL] Tampered package was accepted!")
        sys.exit(1)
    except CryptoError as e:
        print(f"  [PASS] Tampering detected by AES-GCM GHASH tag: \"{e}\"")

    # 7. SHA-256 integrity
    print("\n[Step 7] SHA-256 integrity verification on modified file...")
    modified = sample_content + b"\n[TAMPERED BYTE]"
    is_valid, mod_hash = verify_file_integrity(modified, orig_hash)
    print(f"  Reference SHA-256: {orig_hash}")
    print(f"  Modified SHA-256:  {mod_hash}")
    assert not is_valid, "FAIL: should have detected modification!"
    print("  [PASS] Modification detected by SHA-256 avalanche effect!")

    # 8. Complete Flask API Workflow: PDF -> Encrypt -> Download .sfe -> Decrypt -> Download PDF
    print("\n[Step 8] Testing Complete Flask REST API & Direct Download Workflow...")
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        # A. Health
        r = c.get("/api/health")
        assert r.status_code == 200
        print("  [PASS] GET /api/health -> 200 OK")

        # B. Encrypt PDF -> Returns binary file directly
        r = c.post(
            "/api/encrypt",
            data={"file": (io.BytesIO(sample_content), original_filename), "password": correct_password},
            content_type="multipart/form-data"
        )
        assert r.status_code == 200
        assert r.content_type == "application/octet-stream"
        assert r.data[:4] == b"SFE1"
        assert r.headers["X-Original-Filename"] == original_filename
        assert r.headers["X-Encrypted-Filename"] == f"{original_filename}.sfe"
        disp = r.headers["Content-Disposition"]
        assert f'filename="{original_filename}.sfe"' in disp
        sfe_downloaded_bytes = r.data
        print(f"  [PASS] POST /api/encrypt -> 200 OK (Content-Disposition: {disp})")

        # C. Decrypt .sfe -> Returns recovered binary file directly
        dec_r = c.post(
            "/api/decrypt",
            data={"file": (io.BytesIO(sfe_downloaded_bytes), f"{original_filename}.sfe"), "password": correct_password},
            content_type="multipart/form-data"
        )
        assert dec_r.status_code == 200
        assert dec_r.content_type == "application/octet-stream"
        assert dec_r.headers["X-Original-Filename"] == original_filename
        assert dec_r.headers["X-Authenticated"] == "True"
        assert dec_r.headers["X-Original-Hash"] == orig_hash
        dec_disp = dec_r.headers["Content-Disposition"]
        assert f'filename="{original_filename}"' in dec_disp
        recovered_pdf_bytes = dec_r.data
        print(f"  [PASS] POST /api/decrypt -> 200 OK (Content-Disposition: {dec_disp})")

        # D. Final verification: PDF byte-for-byte and hash check
        recovered_hash = calculate_sha256(recovered_pdf_bytes)
        assert recovered_pdf_bytes == sample_content
        assert recovered_hash == orig_hash
        print(f"  [PASS] Recovered PDF is 100% byte-for-byte IDENTICAL (Hash: {recovered_hash})")

        # E. Decrypt with wrong password returns 400 with generic error
        bad_r = c.post(
            "/api/decrypt",
            data={"file": (io.BytesIO(sfe_downloaded_bytes), f"{original_filename}.sfe"), "password": wrong_password},
            content_type="multipart/form-data"
        )
        assert bad_r.status_code == 400
        assert bad_r.get_json()["success"] is False
        print("  [PASS] POST /api/decrypt (wrong password) -> 400 Bad Request")

    print("\n" + "=" * 70)
    print("ALL VERIFICATION PHASES COMPLETED WITH ZERO ERRORS!")
    print("=" * 70)


if __name__ == "__main__":
    run_full_demonstration()
