"""
Live client test verifying the complete workflow with user filename:
EXP2(RAJ THAKUR , ROLL NO 59).pdf -> Encrypt -> Download .sfe -> Decrypt -> Download original -> Hash compare.
"""
import io
import sys
from pathlib import Path

if sys.platform.startswith("win"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app import create_app
from backend.hashing import calculate_sha256


def test_live_workflow_with_test_client():
    """Verify complete workflow preserving spaces and parentheses in filename."""
    original_filename = "EXP2(RAJ THAKUR , ROLL NO 59).pdf"
    sample_content = b"%PDF-1.4\n1 0 obj\n<< /Title (NSC Project Report) >>\nendobj\n" * 40
    orig_hash = calculate_sha256(sample_content)
    password = "LiveTestPassword#2026"

    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        # 1. POST /api/encrypt -> Returns binary file directly
        enc_res = client.post(
            "/api/encrypt",
            data={"file": (io.BytesIO(sample_content), original_filename), "password": password},
            content_type="multipart/form-data"
        )
        assert enc_res.status_code == 200
        assert enc_res.content_type == "application/octet-stream"
        assert enc_res.headers["X-Original-Filename"] == original_filename
        assert enc_res.headers["X-Encrypted-Filename"] == f"{original_filename}.sfe"
        assert f'filename="{original_filename}.sfe"' in enc_res.headers["Content-Disposition"]
        sfe_bytes = enc_res.data
        assert sfe_bytes[:4] == b"SFE1"

        # 2. POST /api/decrypt -> Returns binary original file directly
        dec_res = client.post(
            "/api/decrypt",
            data={"file": (io.BytesIO(sfe_bytes), f"{original_filename}.sfe"), "password": password},
            content_type="multipart/form-data"
        )
        assert dec_res.status_code == 200
        assert dec_res.content_type == "application/octet-stream"
        assert dec_res.headers["X-Original-Filename"] == original_filename
        assert dec_res.headers["X-Authenticated"] == "True"
        assert dec_res.headers["X-Original-Hash"] == orig_hash
        assert f'filename="{original_filename}"' in dec_res.headers["Content-Disposition"]
        recovered_bytes = dec_res.data

        # 3. Verify byte parity and SHA-256 match
        assert recovered_bytes == sample_content
        assert calculate_sha256(recovered_bytes) == orig_hash


if __name__ == "__main__":
    test_live_workflow_with_test_client()
    print("Live client test passed successfully!")
