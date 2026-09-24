"""
Flask REST API and Web Server for Secure File Integrity & Encryption Tool.
Provides endpoints for file encryption, authenticated decryption, SHA-256 hashing, and integrity verification.
"""

import os
import re
import sys
from pathlib import Path
from urllib.parse import quote

# Allow direct execution: `python backend/app.py` or as package: `python -m backend.app`
if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from backend.config import (
        FRONTEND_FOLDER,
        GENERIC_DECRYPTION_ERROR,
        MAX_CONTENT_LENGTH,
        OUTPUT_FOLDER,
        PBKDF2_ITERATIONS,
    )
    from backend.crypto import CryptoError, decrypt_file_data, encrypt_file_data
    from backend.hashing import calculate_sha256, compare_hashes, verify_file_integrity
else:
    from .config import (
        FRONTEND_FOLDER,
        GENERIC_DECRYPTION_ERROR,
        MAX_CONTENT_LENGTH,
        OUTPUT_FOLDER,
        PBKDF2_ITERATIONS,
    )
    from .crypto import CryptoError, decrypt_file_data, encrypt_file_data
    from .hashing import calculate_sha256, compare_hashes, verify_file_integrity

from flask import Flask, jsonify, make_response, request, send_file, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge


def safe_filename(name: str) -> str:
    """
    Sanitize an uploaded filename safely without stripping spaces, parentheses, or commas.
    Protects against path traversal (../, \\, /, null bytes, drive letters).
    Example:
        'EXP2(RAJ THAKUR , ROLL NO 59).pdf' -> 'EXP2(RAJ THAKUR , ROLL NO 59).pdf'
    """
    if not name:
        return "secured_file.bin"
    # Extract basename only to prevent directory traversal
    base = os.path.basename(name).strip()
    # Remove null bytes
    base = base.replace("\x00", "")
    # Remove path traversal characters
    base = base.replace("/", "").replace("\\", "")
    # Remove filesystem forbidden characters on Windows & Linux: < > : " / \ | ? * and control chars
    base = re.sub(r'[\<\>\:\"\/\\\|\?\*\x00-\x1f]', "", base)
    # Prevent directory traversal dots
    while ".." in base:
        base = base.replace("..", ".")
    base = base.strip(". ")
    return base or "secured_file.bin"


def build_attachment_response(data: bytes, filename: str, extra_headers: dict = None):
    """
    Build a direct binary file download response.
    RFC 6266 + RFC 5987 Content-Disposition guarantees exact filename preservation
    across Chrome, Edge, Firefox, and Safari with zero UUID generation.
    """
    response = make_response(data)
    response.headers["Content-Type"] = "application/octet-stream"
    response.headers["Content-Length"] = str(len(data))

    # Escape double quotes for ASCII filename param
    safe_ascii = filename.replace('"', '\\"')
    utf8_name = quote(filename, safe="")

    response.headers["Content-Disposition"] = (
        f'attachment; filename="{safe_ascii}"; filename*=UTF-8\'\'{utf8_name}'
    )

    expose_headers = [
        "Content-Disposition",
        "Content-Length",
        "Content-Type",
    ]

    if extra_headers:
        for k, v in extra_headers.items():
            response.headers[k] = str(v)
            expose_headers.append(k)

    response.headers["Access-Control-Expose-Headers"] = ", ".join(expose_headers)
    return response


def create_app() -> Flask:
    app = Flask(__name__, static_folder=str(FRONTEND_FOLDER), static_url_path="")
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

    # Disable browser caching on all responses to ensure changes reflect immediately
    @app.after_request
    def add_no_cache_headers(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response

    # --- Frontend Static Routes ---

    @app.route("/")
    def index():
        """Serve the main single-page application."""
        return send_from_directory(FRONTEND_FOLDER, "index.html")

    @app.route("/<path:filename>")
    def static_files(filename):
        """Serve CSS, JS, and assets safely."""
        safe_name = os.path.basename(filename)
        return send_from_directory(FRONTEND_FOLDER, safe_name)

    # --- API Endpoints ---

    @app.route("/api/health", methods=["GET"])
    def health_check():
        """Health and system status check endpoint."""
        return jsonify({
            "status": "healthy",
            "service": "Secure File Integrity & Encryption Tool",
            "version": "1.0.0",
            "ciphers": ["AES-256-GCM"],
            "kdf": "PBKDF2-HMAC-SHA256",
            "hash": "SHA-256",
            "pbkdf2_iterations": PBKDF2_ITERATIONS,
        }), 200

    @app.route("/api/encrypt", methods=["POST"])
    def encrypt_file_endpoint():
        """
        Encrypt an uploaded file using AES-256-GCM and PBKDF2 key derivation.
        1. Encrypts the file and packages it into an authenticated SFE container.
        2. Physically saves the .sfe file to disk in output/<filename>.sfe.
        3. Returns the encrypted binary file DIRECTLY as the HTTP response
           with Content-Type: application/octet-stream and Content-Disposition: attachment.
           Metadata is included in custom X- response headers.
        """
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file part provided."}), 400

        uploaded_file = request.files["file"]
        if not uploaded_file or uploaded_file.filename == "":
            return jsonify({"success": False, "error": "No file selected."}), 400

        password = request.form.get("password", "").strip()
        if not password:
            return jsonify({"success": False, "error": "Password cannot be empty."}), 400

        clean_name = safe_filename(uploaded_file.filename)
        file_bytes = uploaded_file.read()

        if len(file_bytes) > MAX_CONTENT_LENGTH:
            return jsonify({"success": False, "error": "File exceeds maximum permitted size limit."}), 413

        try:
            result = encrypt_file_data(
                file_bytes=file_bytes,
                filename=clean_name,
                password=password,
                iterations=PBKDF2_ITERATIONS,
            )
        except ValueError as ve:
            return jsonify({"success": False, "error": str(ve)}), 400
        except Exception:
            return jsonify({"success": False, "error": "Encryption processing failed."}), 500

        sfe_filename = f"{clean_name}.sfe"
        OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
        sfe_path = OUTPUT_FOLDER / sfe_filename

        # Write physical file to output/
        with open(sfe_path, "wb") as f:
            f.write(result.encrypted_package)

        sfe_size = sfe_path.stat().st_size

        # Server-side logging per specification
        print("\n" + "=" * 50)
        print("ENCRYPTION SUCCESSFUL - SFE CONTAINER CREATED")
        print(f"Original filename:\n{result.original_filename}\n")
        print(f"Generated SFE filename:\n{sfe_filename}\n")
        print(f"SFE file path:\n{sfe_path.resolve()}\n")
        print(f"SFE file size:\n{sfe_size} bytes")
        print("=" * 50 + "\n", flush=True)

        download_url = f"/api/download/file/{quote(sfe_filename)}"

        # Return the actual binary file directly
        return build_attachment_response(
            data=result.encrypted_package,
            filename=sfe_filename,
            extra_headers={
                "X-Original-Filename": result.original_filename,
                "X-Encrypted-Filename": sfe_filename,
                "X-Original-Hash": result.original_hash,
                "X-Algorithm": result.algorithm,
                "X-KDF": result.kdf,
                "X-Original-Size": str(len(file_bytes)),
                "X-Encrypted-Size": str(sfe_size),
                "X-Download-Url": download_url,
            },
        )

    @app.route("/api/decrypt", methods=["POST"])
    def decrypt_file_endpoint():
        """
        Decrypt an uploaded .sfe package and verify authenticity.
        1. Authenticates ciphertext and decrypts file.
        2. Physically saves the recovered file to disk in output/<original_filename>.
        3. Returns the recovered binary file DIRECTLY as the HTTP response
           with Content-Type: application/octet-stream and Content-Disposition: attachment.
           Metadata is included in custom X- response headers.
        """
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file part provided."}), 400

        uploaded_file = request.files["file"]
        if not uploaded_file or uploaded_file.filename == "":
            return jsonify({"success": False, "error": "No file selected."}), 400

        password = request.form.get("password", "").strip()
        if not password:
            return jsonify({"success": False, "error": "Password cannot be empty."}), 400

        package_bytes = uploaded_file.read()
        if len(package_bytes) > MAX_CONTENT_LENGTH:
            return jsonify({"success": False, "error": "File exceeds maximum permitted size limit."}), 413

        try:
            result = decrypt_file_data(
                package_bytes=package_bytes,
                password=password,
                iterations=PBKDF2_ITERATIONS,
            )
        except CryptoError:
            return jsonify({"success": False, "error": GENERIC_DECRYPTION_ERROR}), 400
        except Exception:
            return jsonify({"success": False, "error": GENERIC_DECRYPTION_ERROR}), 400

        recovered_filename = safe_filename(result.original_filename)
        OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
        recovered_path = OUTPUT_FOLDER / recovered_filename

        # Write physical file to output/
        with open(recovered_path, "wb") as f:
            f.write(result.decrypted_data)

        recovered_size = recovered_path.stat().st_size

        # Server-side logging per specification
        print("\n" + "=" * 50)
        print("DECRYPTION SUCCESSFUL - FILE RECOVERED")
        print(f"Original filename:\n{result.original_filename}\n")
        print(f"Recovered filename:\n{recovered_filename}\n")
        print(f"Recovered file path:\n{recovered_path.resolve()}\n")
        print(f"Recovered file size:\n{recovered_size} bytes")
        print("=" * 50 + "\n", flush=True)

        download_url = f"/api/download/file/{quote(recovered_filename)}"

        # Return the actual recovered binary file directly
        return build_attachment_response(
            data=result.decrypted_data,
            filename=recovered_filename,
            extra_headers={
                "X-Original-Filename": result.original_filename,
                "X-Original-Hash": result.original_hash,
                "X-Algorithm": result.algorithm,
                "X-Authenticated": str(result.authenticated),
                "X-File-Size": str(recovered_size),
                "X-Download-Url": download_url,
            },
        )

    @app.route("/api/download/file/<path:filename>", methods=["GET"])
    def download_saved_file(filename):
        """
        Direct HTTP file download endpoint.
        Serves the physical file from OUTPUT_FOLDER using Flask send_file().
        """
        clean_name = safe_filename(os.path.basename(filename))
        file_path = OUTPUT_FOLDER / clean_name

        if not file_path.exists() or not file_path.is_file():
            return jsonify({"success": False, "error": f"File '{clean_name}' not found."}), 404

        response = send_file(
            file_path,
            as_attachment=True,
            download_name=clean_name,
            mimetype="application/octet-stream",
        )
        utf8_name = quote(clean_name, safe="")
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{clean_name}"; filename*=UTF-8\'\'{utf8_name}'
        )
        return response

    @app.route("/api/hash", methods=["POST"])
    def calculate_hash_endpoint():
        """
        Calculate the SHA-256 hash of an uploaded file.
        """
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file part provided."}), 400

        uploaded_file = request.files["file"]
        if not uploaded_file or uploaded_file.filename == "":
            return jsonify({"success": False, "error": "No file selected."}), 400

        clean_name = safe_filename(uploaded_file.filename)
        file_bytes = uploaded_file.read()

        if len(file_bytes) > MAX_CONTENT_LENGTH:
            return jsonify({"success": False, "error": "File exceeds maximum permitted size limit."}), 413

        sha256_hex = calculate_sha256(file_bytes)

        return jsonify({
            "success": True,
            "sha256": sha256_hex,
            "filename": clean_name,
            "size": len(file_bytes),
            "algorithm": "SHA-256",
        }), 200

    @app.route("/api/verify", methods=["POST"])
    def verify_integrity_endpoint():
        """
        Verify the integrity of an uploaded file against a reference SHA-256 hash.
        """
        if "file" not in request.files:
            return jsonify({"success": False, "error": "No file part provided."}), 400

        uploaded_file = request.files["file"]
        if not uploaded_file or uploaded_file.filename == "":
            return jsonify({"success": False, "error": "No file selected."}), 400

        reference_hash = request.form.get("reference_hash", "").strip()
        if not reference_hash:
            return jsonify({"success": False, "error": "Reference SHA-256 hash is required."}), 400

        clean_name = safe_filename(uploaded_file.filename)
        file_bytes = uploaded_file.read()

        if len(file_bytes) > MAX_CONTENT_LENGTH:
            return jsonify({"success": False, "error": "File exceeds maximum permitted size limit."}), 413

        is_verified, current_hash = verify_file_integrity(file_bytes, reference_hash)

        return jsonify({
            "success": True,
            "verified": is_verified,
            "current_hash": current_hash,
            "reference_hash": reference_hash,
            "filename": clean_name,
            "size": len(file_bytes),
            "status": "Verified" if is_verified else "Integrity Check Failed",
        }), 200

    # --- Error Handlers ---

    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(e):
        return jsonify({"success": False, "error": "File size exceeds the 50 MB limit."}), 413

    @app.errorhandler(404)
    def handle_not_found(e):
        return jsonify({"success": False, "error": "Resource not found."}), 404

    @app.errorhandler(500)
    def handle_internal_error(e):
        return jsonify({"success": False, "error": "An internal server error occurred."}), 500

    return app


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting Secure File Integrity & Encryption Tool on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
