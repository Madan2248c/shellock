"""
Shellock - Secure encryption for configuration files using AES-256-GCM + Argon2id.

This package provides both a CLI and Python API for encrypting and decrypting
configuration files with strong cryptographic defaults.
"""

__version__ = "0.1.2"
__author__ = "Madan Gopal"
__email__ = "madangopalboddu123@gmail.com"

# Public API exports
from .api import (
    decrypt_file,
    decrypt_file_key,
    decrypt_file_private,
    encrypt_file,
    encrypt_file_key,
    encrypt_file_public,
)
from .crypto import (
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    KEY_SIZE,
    MAGIC_HEADER,
    MAGIC_HEADER_ASYMMETRIC,
    NONCE_SIZE,
    SALT_SIZE,
    TAG_SIZE,
    AsymmetricEnvelope,
    Envelope,
    decrypt_bytes,
    decrypt_bytes_key,
    decrypt_bytes_private,
    derive_key_from_passphrase,
    encrypt_bytes,
    encrypt_bytes_key,
    encrypt_bytes_public,
    generate_keypair,
    secure_compare,
)
from .exceptions import (
    AuthenticationError,
    EnvCryptError,
    InvalidFileFormatError,
    SecureMemoryError,
)

__all__ = [
    "__version__",
    # Exceptions
    "EnvCryptError",
    "InvalidFileFormatError",
    "AuthenticationError",
    "SecureMemoryError",
    # Byte-level crypto functions
    "derive_key_from_passphrase",
    "secure_compare",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_bytes_key",
    "decrypt_bytes_key",
    "generate_keypair",
    "encrypt_bytes_public",
    "decrypt_bytes_private",
    # Data classes
    "Envelope",
    "AsymmetricEnvelope",
    # Constants
    "SALT_SIZE",
    "KEY_SIZE",
    "NONCE_SIZE",
    "TAG_SIZE",
    "MAGIC_HEADER",
    "MAGIC_HEADER_ASYMMETRIC",
    "ARGON2_MEMORY_COST",
    "ARGON2_TIME_COST",
    "ARGON2_PARALLELISM",
    # File-based API
    "encrypt_file",
    "decrypt_file",
    "encrypt_file_public",
    "decrypt_file_private",
    "encrypt_file_key",
    "decrypt_file_key",
]
