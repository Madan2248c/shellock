"""
Custom exception classes for Shellock.

This module defines the exception hierarchy used throughout the Shellock package
to provide clear error handling and security-focused error messages.
"""


class EnvCryptError(Exception):
    """Base exception for all Shellock errors."""

    pass


class InvalidFileFormatError(EnvCryptError):
    """
    Raised when the encrypted file format is invalid.

    This includes cases where:
    - Magic header doesn't match expected value
    - File is too short to contain required fields
    - Envelope structure is malformed
    """

    pass


class AuthenticationError(EnvCryptError):
    """
    Raised when decryption fails due to wrong passphrase or tampering.

    This includes cases where:
    - Wrong passphrase provided
    - Ciphertext has been tampered with
    - Authentication tag verification fails
    - Private key doesn't match encrypted data
    """

    pass


class SecureMemoryError(EnvCryptError):
    """
    Raised when secure memory operations fail.

    This includes cases where:
    - Memory zeroization fails
    - Secure memory allocation fails
    - Memory cleanup operations encounter errors
    """

    pass
