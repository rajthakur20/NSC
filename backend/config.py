"""
Configuration module for Secure File Integrity & Encryption Tool.
Defines security parameters, cryptographic constants, and file processing limits.
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
OUTPUT_FOLDER = BASE_DIR / "output"
FRONTEND_FOLDER = BASE_DIR / "frontend"

# Cryptographic Parameters
# Container Magic Identifier (4 bytes)
MAGIC_HEADER = b"SFE1"  # Secure File Encrypted version 1

# PBKDF2 Key Derivation Configuration
# 100,000 iterations provides a solid balance of high security and responsive performance
PBKDF2_ITERATIONS = 100000
PBKDF2_SALT_BYTES = 16  # 128-bit cryptographically secure salt

# AES-256-GCM Configuration
AES_KEY_BYTES = 32      # 256 bits
GCM_NONCE_BYTES = 12    # 96 bits standard nonce length for AES-GCM
GCM_TAG_BYTES = 16      # 128-bit authentication tag

# Application Security Parameters
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB max upload limit
ALLOWED_EXTENSIONS = None  # None allows all file types for encryption

# Generic error message to prevent oracle attacks and information leakage
GENERIC_DECRYPTION_ERROR = (
    "Decryption failed. The password may be incorrect or the encrypted file may have been modified."
)
