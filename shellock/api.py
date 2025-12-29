"""
File-based API for Shellock.

This module provides high-level file operations built on top of the crypto module
for both symmetric and asymmetric encryption.
"""

import base64
import os
import stat
from pathlib import Path
from typing import Optional

from .crypto import (
    KEY_SIZE,
    decrypt_bytes,
    decrypt_bytes_key,
    decrypt_bytes_private,
    encrypt_bytes,
    encrypt_bytes_key,
    encrypt_bytes_public,
)
from .exceptions import InvalidFileFormatError

# File permission for output files (owner read/write only)
SECURE_FILE_PERMISSIONS = stat.S_IRUSR | stat.S_IWUSR  # 0o600


def _read_file_bytes(path: str) -> bytes:
    """
    Read file contents as bytes with proper error handling.

    Args:
        path: Path to the file to read

    Returns:
        File contents as bytes

    Raises:
        FileNotFoundError: If the file does not exist
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    return file_path.read_bytes()


def _write_file_bytes(path: str, data: bytes) -> None:
    """
    Write bytes to file with secure permissions.

    Creates parent directories if they don't exist.
    Sets file permissions to 600 (owner read/write only).

    Args:
        path: Path to the output file
        data: Bytes to write

    Raises:
        FileNotFoundError: If the output directory does not exist
    """
    file_path = Path(path)

    # Check if parent directory exists
    parent_dir = file_path.parent
    if parent_dir and not parent_dir.exists():
        raise FileNotFoundError(f"Directory not found: {parent_dir}")

    # Write the file
    file_path.write_bytes(data)

    # Set secure permissions (600)
    os.chmod(path, SECURE_FILE_PERMISSIONS)


def _read_symmetric_key_file(key_file_path: str) -> bytes:
    """
    Read and decode a base64-encoded symmetric key file.

    Args:
        key_file_path: Path to the base64-encoded key file

    Returns:
        32-byte symmetric key

    Raises:
        FileNotFoundError: If the key file does not exist
        InvalidFileFormatError: If the key format is invalid
    """
    key_data = _read_file_bytes(key_file_path)

    try:
        # Decode base64 key (strip whitespace first)
        key_bytes = base64.b64decode(key_data.strip())
    except Exception as e:
        raise InvalidFileFormatError(f"Invalid key file format: {e}")

    # Validate key size
    if len(key_bytes) != KEY_SIZE:
        raise InvalidFileFormatError(
            f"Invalid key size: expected {KEY_SIZE} bytes, got {len(key_bytes)}"
        )

    return key_bytes


def encrypt_file(in_path: str, out_path: str, passphrase: str) -> None:
    """
    Encrypt a file and write the result to another file.

    Reads the input file, encrypts its contents using AES-256-GCM with
    Argon2id key derivation, and writes the encrypted envelope to the
    output path with secure permissions (600).

    Args:
        in_path: Path to plaintext input file
        out_path: Path to write encrypted output
        passphrase: User-provided secret string for key derivation

    Raises:
        FileNotFoundError: If input file or output directory doesn't exist
    """
    # Read input file
    plaintext = _read_file_bytes(in_path)

    # Encrypt the data
    encrypted_data = encrypt_bytes(plaintext, passphrase)

    # Write encrypted output with secure permissions
    _write_file_bytes(out_path, encrypted_data)


def decrypt_file(in_path: str, out_path: str, passphrase: str) -> None:
    """
    Decrypt an encrypted file and write the result to another file.

    Reads the encrypted file, decrypts its contents using AES-256-GCM with
    Argon2id key derivation, and writes the plaintext to the output path
    with secure permissions (600).

    Args:
        in_path: Path to encrypted input file
        out_path: Path to write decrypted output
        passphrase: User-provided secret string for key derivation

    Raises:
        FileNotFoundError: If input file or output directory doesn't exist
        InvalidFileFormatError: If file format is invalid
        AuthenticationError: If passphrase is wrong or data is tampered
    """
    # Read encrypted file
    encrypted_data = _read_file_bytes(in_path)

    # Decrypt the data
    plaintext = decrypt_bytes(encrypted_data, passphrase)

    # Write decrypted output with secure permissions
    _write_file_bytes(out_path, plaintext)


def encrypt_file_public(in_path: str, out_path: str, public_key_path: str) -> None:
    """
    Encrypt a file with a public key and write the result to another file.

    Uses hybrid encryption: generates a random symmetric key, encrypts the data
    with AES-256-GCM, and encrypts the symmetric key with the recipient's
    X25519 public key.

    Args:
        in_path: Path to plaintext input file
        out_path: Path to write encrypted output
        public_key_path: Path to X25519 public key file (PEM format)

    Raises:
        FileNotFoundError: If input file or public key file doesn't exist
        InvalidFileFormatError: If public key format is invalid
    """
    # Read input file
    plaintext = _read_file_bytes(in_path)

    # Read public key
    public_key_pem = _read_file_bytes(public_key_path)

    # Encrypt the data with public key
    encrypted_data = encrypt_bytes_public(plaintext, public_key_pem)

    # Write encrypted output with secure permissions
    _write_file_bytes(out_path, encrypted_data)


def decrypt_file_private(
    in_path: str, out_path: str, private_key_path: str, passphrase: Optional[str] = None
) -> None:
    """
    Decrypt an encrypted file with a private key and write the result to another file.

    Uses hybrid decryption: decrypts the symmetric key with the X25519 private key,
    then decrypts the data with AES-256-GCM.

    Args:
        in_path: Path to encrypted input file
        out_path: Path to write decrypted output
        private_key_path: Path to X25519 private key file (PEM format)
        passphrase: Optional passphrase if private key is encrypted

    Raises:
        FileNotFoundError: If input file or private key file doesn't exist
        InvalidFileFormatError: If file format or key format is invalid
        AuthenticationError: If private key is wrong or data is tampered
    """
    # Read encrypted file
    encrypted_data = _read_file_bytes(in_path)

    # Read private key
    private_key_pem = _read_file_bytes(private_key_path)

    # Decrypt the data with private key
    plaintext = decrypt_bytes_private(encrypted_data, private_key_pem, passphrase)

    # Write decrypted output with secure permissions
    _write_file_bytes(out_path, plaintext)


def encrypt_file_key(in_path: str, out_path: str, key_file_path: str) -> None:
    """
    Encrypt a file with a symmetric key file and write the result to another file.

    Uses the symmetric key directly for AES-256-GCM encryption without
    key derivation.

    Args:
        in_path: Path to plaintext input file
        out_path: Path to write encrypted output
        key_file_path: Path to base64-encoded symmetric key file

    Raises:
        FileNotFoundError: If input file or key file doesn't exist
        InvalidFileFormatError: If key file format is invalid
    """
    # Read input file
    plaintext = _read_file_bytes(in_path)

    # Read and decode symmetric key
    symmetric_key = _read_symmetric_key_file(key_file_path)

    # Encrypt the data with symmetric key
    encrypted_data = encrypt_bytes_key(plaintext, symmetric_key)

    # Write encrypted output with secure permissions
    _write_file_bytes(out_path, encrypted_data)


def decrypt_file_key(in_path: str, out_path: str, key_file_path: str) -> None:
    """
    Decrypt an encrypted file with a symmetric key file and write the result to another file.

    Uses the symmetric key directly for AES-256-GCM decryption without
    key derivation.

    Args:
        in_path: Path to encrypted input file
        out_path: Path to write decrypted output
        key_file_path: Path to base64-encoded symmetric key file

    Raises:
        FileNotFoundError: If input file or key file doesn't exist
        InvalidFileFormatError: If file format or key format is invalid
        AuthenticationError: If key is wrong or data is tampered
    """
    # Read encrypted file
    encrypted_data = _read_file_bytes(in_path)

    # Read and decode symmetric key
    symmetric_key = _read_symmetric_key_file(key_file_path)

    # Decrypt the data with symmetric key
    plaintext = decrypt_bytes_key(encrypted_data, symmetric_key)

    # Write decrypted output with secure permissions
    _write_file_bytes(out_path, plaintext)
