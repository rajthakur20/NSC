# Secure File Integrity & Encryption Tool

> **Subject:** Network Security and Cryptography (NSC)  
> **Academic Level:** Undergraduate Engineering Project  
> **Architecture:** Zero-Knowledge, In-Memory Cryptographic Processing (No Database)

---

## 1. Problem Statement

In contemporary computing environments, files transferred across open networks or stored on untrusted cloud storage systems face severe threats of unauthorized interception, eavesdropping, and covert data tampering. Traditional file protection solutions often suffer from:

1. **Confidentiality-only encryption** (e.g., AES in ECB or CBC mode without authentication), leaving data vulnerable to bit-flipping and padding oracle attacks.
2. **Weak password-to-key mapping**, making systems trivial to breach via dictionary and GPU rainbow table attacks.
3. **Persistent credential storage**, where databases leak master keys or plaintext files upon server compromise.
4. **Lack of tamper evidence**, making it impossible to know whether a file was altered in transit.

There is a critical need for an authenticated, tamper-evident, zero-storage file encryption and integrity verification system that implements modern cryptographic standards.

---

## 2. Objectives

The primary objectives of this project are:
- **Confidentiality:** Implement **AES-256-GCM** (Galois/Counter Mode) authenticated symmetric encryption.
- **Key Protection:** Use **PBKDF2-HMAC-SHA256** with 100,000 iterations and cryptographically random 128-bit salts to derive high-entropy 256-bit encryption keys from user passphrases.
- **Tamper Evidence & Authenticity:** Leverage the GCM 128-bit authentication tag and Additional Authenticated Data (AAD) container headers to reject modified or forged files.
- **Integrity Verification:** Provide stand-alone **SHA-256** cryptographic digest generation and constant-time integrity comparison to detect bit-level modifications.
- **Zero-Storage Privacy:** Process all files in-memory using ephemeral streams without storing passwords, encryption keys, or plaintext files on disk or in a database.

---

## 3. Features

* 🔐 **Authenticated File Encryption:** Encrypt any file type into a secure `.sfe` (Secure File Encrypted) container.
* 🔓 **Tamper-Resistant Decryption:** Decrypt `.sfe` files only when the exact password is provided and the file is unaltered.
* 🛡️ **SHA-256 Hashing Tool:** Compute 64-character hexadecimal SHA-256 digests with one-click copy.
* ⚖️ **Constant-Time Integrity Verification:** Compare file hashes against reference values safely against timing attacks.
* 📊 **Interactive Security Report:** Presentation-ready visual report displayed after every operation (ideal for viva demonstrations and screenshots).
* 🎯 **Password Strength Analyzer:** Real-time entropy evaluation and confirmation validation.
* 💡 **Educational Cryptography Suite:** Built-in "How It Works" guide explaining AES-GCM, SHA-256, PBKDF2, Salts, and Nonces.
* 🛡️ **Defensive Security Controls:** Path traversal sanitization, upload size limits (50 MB), and generic error messages against oracle attacks.

---

## 4. Technology Stack

* **Frontend:**
  * HTML5 (Semantic structure & accessible forms)
  * CSS3 (Cybersecurity dark theme, cyan/sapphire accents, glassmorphism, responsive grid)
  * Vanilla JavaScript (ES6+, asynchronous Fetch API, Blob streaming, DOM manipulation)
* **Backend:**
  * Python 3
  * Flask (Lightweight REST API & static file server)
  * Werkzeug (Filename sanitization & request limits)
* **Cryptography:**
  * `cryptography` library (`hazmat` primitives)
  * `AES-256-GCM` (NIST SP 800-38D)
  * `PBKDF2-HMAC-SHA256` (RFC 8018)
  * `SHA-256` (FIPS PUB 180-4)
  * `secrets` / `os.urandom` (CSPRNG)
  * `hmac.compare_digest` (Constant-time string comparison)
* **Testing:**
  * `pytest` (Unit and integration test suites)

---

## 5. System Architecture

```
+-------------------------------------------------------------------------------+
|                               FRONTEND CLIENT                                 |
|  [ Dashboard ]  [ Encrypt ]  [ Decrypt ]  [ Verify ]  [ How It Works ]        |
+---------------------------------------+---------------------------------------+
                                        | (HTTPS / REST Multipart Form-Data)
                                        v
+-------------------------------------------------------------------------------+
|                            FLASK BACKEND (app.py)                             |
|  - Filename Sanitization (secure_filename)                                    |
|  - Size & Payload Validation                                                  |
|  - Ephemeral In-Memory Processing (No Database, No Permanent File Storage)    |
+-------------------+-----------------------------------+-----------------------+
                    |                                   |
                    v                                   v
+-----------------------------------+   +---------------------------------------+
|        CRYPTO ENGINE (crypto.py)  |   |        HASHING ENGINE (hashing.py)    |
| - CSPRNG Salt (16B) & Nonce (12B) |   | - SHA-256 (64-char Hex Digest)        |
| - PBKDF2-HMAC-SHA256 (100k rounds)|   | - Constant-Time Digest Match          |
| - AES-256-GCM (Ciphertext + Tag)  |   |   (hmac.compare_digest)               |
| - .sfe Binary Container Packager  |   +---------------------------------------+
+-----------------------------------+
```

---

## 6. Project Folder Structure

```
secure-file-integrity-tool/
│
├── backend/
│   ├── __init__.py           # Package initializer
│   ├── app.py                # Flask application & REST API routes
│   ├── crypto.py             # AES-256-GCM & PBKDF2 key derivation logic
│   ├── hashing.py            # SHA-256 digest & constant-time comparator
│   └── config.py             # Security constants & configuration
│
├── frontend/
│   ├── index.html            # Main SPA interface
│   ├── style.css             # Cyberpunk dark theme styles
│   └── script.js             # Client-side API interactions & UI handlers
│
├── tests/
│   ├── test_crypto.py        # Unit tests for cryptographic primitives
│   ├── test_hashing.py       # Unit tests for SHA-256 hashing
│   ├── test_api.py           # Integration tests for Flask endpoints
│   └── test_e2e_demo.py      # End-to-end full system verification
│
├── uploads/
│   └── .gitkeep              # Ephemeral workspace marker
│
├── output/
│   └── .gitkeep              # Ephemeral output marker
│
├── requirements.txt          # Python dependencies
├── README.md                 # Project documentation & viva guide
└── .gitignore                # Git exclusions
```

---

## 7. Encrypted Container Format (`.sfe`)

Files are packaged into a standardized binary format with extension `.sfe` (Secure File Encrypted):

```
+---------------+---------------+---------------+------------------+-------------------+-----------------+-----------------------+
|  MAGIC HEADER |      SALT     |     NONCE     | ORIGINAL SHA-256 | FILENAME LEN (2B) |  ORIGINAL NAME  |   CIPHERTEXT + TAG    |
|   "SFE1" (4B) |   (16 Bytes)  |   (12 Bytes)  |    (32 Bytes)    |  Big-Endian Uint  |   (UTF-8 Str)   |  (AES-GCM Payload)    |
+---------------+---------------+---------------+------------------+-------------------+-----------------+-----------------------+
|<----------------------- Additional Authenticated Data (AAD) ------------------------>|
```

### Why Authenticated Header (AAD)?
The entire header preceding the ciphertext is passed as **Additional Authenticated Data (AAD)** to the AES-GCM cipher during encryption. If an attacker attempts to alter the embedded original filename, salt, nonce, or hash, the AES-GCM Galois hash check fails immediately upon decryption!

---

## 8. Cryptographic Workflows

### 8.1 Encryption Workflow
1. **Read Plaintext:** Client uploads file bytes.
2. **Compute Digest:** Calculate SHA-256 hash of plaintext bytes.
3. **Generate Salt:** Generate 16 cryptographically random bytes (`secrets.token_bytes(16)`).
4. **Derive Key:** Compute 256-bit AES key via `PBKDF2-HMAC-SHA256(password, salt, iterations=100000)`.
5. **Generate Nonce:** Generate fresh 12-byte (96-bit) nonce.
6. **Construct Header:** Format magic bytes `SFE1`, salt, nonce, raw SHA-256 hash, and sanitized filename.
7. **Encrypt & Authenticate:** Encrypt plaintext using `AESGCM.encrypt(nonce, plaintext, associated_data=header)`.
8. **Package & Deliver:** Concatenate header with ciphertext + 16-byte GCM authentication tag into a `.sfe` package for download.

### 8.2 Decryption Workflow
1. **Parse Container:** Read `.sfe` package, verify `SFE1` magic header.
2. **Extract Metadata:** Extract salt, nonce, original SHA-256 hash, and original filename.
3. **Reconstruct AAD:** Rebuild the container header bytes.
4. **Derive Key:** Re-derive 256-bit AES key from user-provided password and extracted salt using PBKDF2.
5. **Authenticated Decrypt:** Execute `AESGCM.decrypt(nonce, ciphertext_and_tag, associated_data=header)`.
6. **Integrity Check:** Compute SHA-256 on recovered plaintext and compare with extracted hash using `hmac.compare_digest`.
7. **Return File:** If authentic, restore the original filename and return decrypted bytes. If tag verification fails, return generic error.

### 8.3 Integrity Verification Workflow
1. User uploads a file and pastes a reference SHA-256 hash.
2. Server calculates `SHA-256(file_bytes)`.
3. Server executes `hmac.compare_digest(current_hash, reference_hash)` in constant time.
4. Result displays `✓ FILE INTEGRITY VERIFIED` or `✗ FILE INTEGRITY CHECK FAILED`.

---

## 9. Security Features & Threat Mitigation

| Security Risk / Attack Vector | Mitigation in this Project |
| :--- | :--- |
| **Bit-Flipping / Ciphertext Tampering** | AES-256-GCM 128-bit GHASH authentication tag rejects any modified byte. |
| **Metadata / Header Tampering** | Container header is bound as Additional Authenticated Data (AAD) in GCM. |
| **Dictionary & GPU Brute Force** | PBKDF2-HMAC-SHA256 with 100,000 iterations creates significant computational work factor. |
| **Rainbow Table Attacks** | 16-byte random salt ensures identical passwords produce completely distinct keys. |
| **Nonce Reuse Attacks** | Fresh 96-bit nonce generated via CSPRNG for every single encryption. |
| **Side-Channel Timing Attacks** | Constant-time string matching (`hmac.compare_digest`) for hash verification. |
| **Padding Oracle Attacks** | AES-GCM is a stream/counter-based AEAD cipher; no PKCS#7 padding is used. |
| **Path Traversal (`../../etc/passwd`)** | Strict `secure_filename` and `os.path.basename` sanitization. |
| **Credential & Key Leaks** | Zero-Database architecture; keys and passwords never saved or logged. |
| **Information Leakage via Errors** | Generic decryption failure message hides whether error was password or tampering. |

---

## 10. Installation & Setup

### Prerequisites
- Python 3.10+ installed on your system.
- `pip` package manager.

### Step 1: Clone or Navigate to Project
```bash
cd secure-file-integrity-tool
```

### Step 2: Install Dependencies
```bash
python -m pip install -r requirements.txt
```

---

## 11. Running the Application

### Start the Flask Server
```bash
python backend/app.py
```

### Access the Web Interface
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 12. Running Automated Tests

Run the complete test suite (30 unit & integration tests):
```bash
python -m pytest tests/ -v
```

Run the End-to-End Cryptographic Demonstration:
```bash
python tests/test_e2e_demo.py
```

---

## 13. REST API Specification

### 1. Health Check
* **Endpoint:** `GET /api/health`
* **Response:**
  ```json
  {
    "status": "healthy",
    "service": "Secure File Integrity & Encryption Tool",
    "ciphers": ["AES-256-GCM"],
    "kdf": "PBKDF2-HMAC-SHA256",
    "hash": "SHA-256",
    "pbkdf2_iterations": 100000
  }
  ```

### 2. Encrypt File
* **Endpoint:** `POST /api/encrypt`
* **Form-Data:** `file` (Binary File), `password` (String)
* **Response (200 OK):**
  ```json
  {
    "success": true,
    "filename": "assignment.pdf",
    "encrypted_filename": "assignment.pdf.sfe",
    "original_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "algorithm": "AES-256-GCM",
    "kdf": "PBKDF2-HMAC-SHA256",
    "encrypted_data_base64": "..."
  }
  ```

### 3. Decrypt File
* **Endpoint:** `POST /api/decrypt`
* **Form-Data:** `file` (`.sfe` File), `password` (String)
* **Response (200 OK):**
  ```json
  {
    "success": true,
    "filename": "assignment.pdf",
    "original_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "algorithm": "AES-256-GCM",
    "authenticated": true,
    "decrypted_data_base64": "..."
  }
  ```
* **Response (400 Bad Request on Failure):**
  ```json
  {
    "success": false,
    "error": "Decryption failed. The password may be incorrect or the encrypted file may have been modified."
  }
  ```

### 4. Compute Hash
* **Endpoint:** `POST /api/hash`
* **Form-Data:** `file` (Binary File)
* **Response:**
  ```json
  {
    "success": true,
    "sha256": "80875c440785dabb38c25c39278f3d167c2a33d563d356e6a75509438859bb20",
    "filename": "document.txt",
    "size": 223
  }
  ```

### 5. Verify Integrity
* **Endpoint:** `POST /api/verify`
* **Form-Data:** `file` (Binary File), `reference_hash` (64-char Hex String)
* **Response:**
  ```json
  {
    "success": true,
    "verified": true,
    "current_hash": "80875c44...",
    "reference_hash": "80875c44...",
    "filename": "document.txt",
    "status": "Verified"
  }
  ```

---

## 14. Viva & Oral Exam Q&A Guide

### Q1: What is AES-256-GCM and why is it preferred over AES-CBC or AES-ECB?
> **Answer:** AES-GCM (Galois/Counter Mode) is an AEAD (Authenticated Encryption with Associated Data) cipher. Unlike ECB (which leaks plaintext patterns) or CBC (which only encrypts without verifying integrity and is prone to padding oracle attacks), GCM provides **both confidentiality and authenticity** simultaneously using counter-mode encryption combined with a Galois authentication tag.

### Q2: Why can't we use a password directly as an AES key?
> **Answer:** Human passwords have low entropy and variable lengths. AES-256 strictly requires an exact 256-bit (32-byte) pseudo-random key. PBKDF2-HMAC-SHA256 converts variable-length passwords into uniform 256-bit keys while applying a salt and 100,000 hashing rounds to slow down brute-force attacks.

### Q3: Why is a Salt necessary if the password is already secret?
> **Answer:** A salt prevents rainbow table (precomputed dictionary) attacks and ensures that two identical passwords derive completely different cryptographic keys. Salts are public and stored openly in the `.sfe` header.

### Q4: Why is Nonce reuse catastrophic in AES-GCM?
> **Answer:** In AES-GCM, reusing a nonce with the same key allows an adversary to XOR two ciphertexts to cancel out the keystream and compute the difference between plaintexts. It also allows recovering the authentication hash subkey (H), destroying integrity protection. We generate a fresh random 96-bit nonce for every encryption.

### Q5: How does the application detect if an encrypted file was modified?
> **Answer:** During decryption, the AES-GCM engine computes a GHASH across the ciphertext and the AAD header and compares it against the 128-bit authentication tag. If even a single bit was modified, the tag mismatch raises an `InvalidTag` exception and the application aborts immediately without producing corrupted plaintext.

### Q6: Why do we use `hmac.compare_digest` instead of `==` for hash comparison?
> **Answer:** Standard string equality (`==`) compares character by character and exits on the first mismatch, leaking information through execution time (timing attack). `hmac.compare_digest` runs in **constant time**, eliminating timing side-channels.

---

## 15. Limitations

- **File Size Limit:** Memory-buffered processing is configured for files up to 50 MB to prevent server memory exhaustion.
- **Symmetric Architecture:** Both encryption and decryption require the same shared password.
- **No Multi-User Access Lists:** Version 1 does not manage user accounts or role-based access control.

---

## 16. Future Scope

The following capabilities are architected for potential Version 2 enhancements:
- **Asymmetric Hybrid Encryption:** RSA-4096 / ECC (Curve25519) public/private key pairs for multi-recipient sharing.
- **Digital Signatures:** ECDSA / Ed25519 digital signatures for non-repudiation.
- **SQLite Operation Audit Trail:** Optional local audit logging of operation timestamps and hash records.
- **Chunked Streaming Cryptography:** Streaming chunked AES-GCM encryption for multi-gigabyte file transfers.
- **Cloud Storage Connectors:** Direct integration with AWS S3 / Google Cloud Storage buckets.

---

## 17. License & Academic Attribution
Developed for academic submission under the **Network Security and Cryptography** curriculum.
