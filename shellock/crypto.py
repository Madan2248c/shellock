"""
Core cryptographic operations for Shellock.

This module contains all cryptographic primitives and envelope handling
for both symmetric and asymmetric encryption.
"""

import secrets
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .exceptions import AuthenticationError, InvalidFileFormatError

# Try to import zeroize for secure memory cleanup
try:
    from zeroize import zeroize

    ZEROIZE_AVAILABLE = True
except ImportError:
    ZEROIZE_AVAILABLE = False

# Constants
MAGIC_HEADER: bytes = b"SHELLOCKv1"  # 10 bytes
MAGIC_HEADER_ASYMMETRIC: bytes = b"SHELLOCKa1"  # 10 bytes for asymmetric
SALT_SIZE: int = 16
NONCE_SIZE: int = 12
TAG_SIZE: int = 16
KEY_SIZE: int = 32

# Argon2id parameters (OWASP recommendations)
ARGON2_MEMORY_COST: int = 65536  # 64 MB
ARGON2_TIME_COST: int = 2
ARGON2_PARALLELISM: int = 4


def _secure_cleanup(data: bytearray) -> None:
    """
    Securely zero out sensitive data in memory.

    Uses zeroize-python if available, otherwise falls back to manual zeroing.

    Args:
        data: Mutable bytearray to be zeroed
    """
    if ZEROIZE_AVAILABLE:
        try:
            zeroize(data)
        except Exception:
            # Fallback to manual zeroing if zeroize fails
            for i in range(len(data)):
                data[i] = 0
    else:
        # Manual zeroing when zeroize is not available
        for i in range(len(data)):
            data[i] = 0


def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte key from passphrase using Argon2id.

    Uses OWASP-recommended parameters for Argon2id:
    - memory_cost: 65536 (64 MB)
    - time_cost: 2
    - parallelism: 4

    Args:
        passphrase: User-provided secret string
        salt: Random 16-byte salt for key derivation

    Returns:
        32-byte derived key suitable for AES-256

    Raises:
        ValueError: If salt is not 16 bytes
    """
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be {SALT_SIZE} bytes, got {len(salt)}")

    # Convert passphrase to bytes
    passphrase_bytes = bytearray(passphrase.encode("utf-8"))

    try:
        # Create Argon2id KDF instance
        kdf = Argon2id(
            salt=salt,
            length=KEY_SIZE,
            iterations=ARGON2_TIME_COST,
            lanes=ARGON2_PARALLELISM,
            memory_cost=ARGON2_MEMORY_COST,
        )

        # Derive the key
        derived_key = kdf.derive(bytes(passphrase_bytes))

        return derived_key
    finally:
        # Securely cleanup passphrase bytes from memory
        _secure_cleanup(passphrase_bytes)


def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Perform constant-time comparison of two byte sequences.

    Uses secrets.compare_digest() to prevent timing attacks.

    Args:
        a: First byte sequence
        b: Second byte sequence

    Returns:
        True if sequences are equal, False otherwise
    """
    return secrets.compare_digest(a, b)


# Envelope header size: magic (10) + salt (16) + nonce (12) + tag (16) = 54 bytes
ENVELOPE_HEADER_SIZE: int = len(MAGIC_HEADER) + SALT_SIZE + NONCE_SIZE + TAG_SIZE


def encrypt_bytes(plaintext: bytes, passphrase: str) -> bytes:
    """
    Encrypt plaintext bytes with passphrase.

    Generates random salt and nonce, derives key using Argon2id,
    and encrypts with AES-256-GCM.

    Args:
        plaintext: Data to encrypt
        passphrase: User-provided secret string for key derivation

    Returns:
        Binary envelope containing: magic header + salt + nonce + tag + ciphertext

    Raises:
        ValueError: If plaintext or passphrase is invalid
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Generate random salt and nonce
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)

    # Create mutable bytearray for derived key to enable secure cleanup
    derived_key = bytearray(derive_key_from_passphrase(passphrase, salt))

    try:
        # Create AES-GCM cipher and encrypt
        aesgcm = AESGCM(bytes(derived_key))

        # AES-GCM encrypt returns ciphertext + tag concatenated
        # The tag is the last 16 bytes
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

        # Split ciphertext and tag (tag is last 16 bytes)
        ciphertext = ciphertext_with_tag[:-TAG_SIZE]
        tag = ciphertext_with_tag[-TAG_SIZE:]

        # Create and serialize envelope
        envelope = Envelope(
            magic=MAGIC_HEADER, salt=salt, nonce=nonce, tag=tag, ciphertext=ciphertext
        )

        return envelope.to_bytes()
    finally:
        # Securely cleanup derived key from memory
        _secure_cleanup(derived_key)


def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
    """
    Decrypt an encrypted envelope with passphrase.

    Parses the envelope, derives key using Argon2id, and decrypts with AES-256-GCM.
    Uses constant-time operations and generic error messages to prevent information leakage.

    Args:
        blob: Binary envelope from encrypt_bytes
        passphrase: User-provided secret string for key derivation

    Returns:
        Original plaintext bytes

    Raises:
        InvalidFileFormatError: If magic header doesn't match or envelope is malformed
        AuthenticationError: If passphrase is wrong or data is tampered
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Parse envelope - this will raise InvalidFileFormatError if format is invalid
    envelope = Envelope.from_bytes(blob)

    # Create mutable bytearray for derived key to enable secure cleanup
    derived_key = bytearray(derive_key_from_passphrase(passphrase, envelope.salt))

    try:
        # Create AES-GCM cipher
        aesgcm = AESGCM(bytes(derived_key))

        # AES-GCM decrypt expects ciphertext + tag concatenated
        ciphertext_with_tag = envelope.ciphertext + envelope.tag

        try:
            # Decrypt and verify authentication tag
            plaintext = aesgcm.decrypt(envelope.nonce, ciphertext_with_tag, None)
            return plaintext
        except InvalidTag:
            # Use generic error message to prevent information leakage
            # Don't reveal whether it was wrong passphrase or tampered data
            raise AuthenticationError("Authentication failed")
    finally:
        # Securely cleanup derived key from memory
        _secure_cleanup(derived_key)


@dataclass
class Envelope:
    """
    Represents a parsed encrypted envelope.

    The binary envelope format is fixed-layout:
    - magic: 10 bytes (b"SHELLOCKv1")
    - salt: 16 bytes (random salt for Argon2id)
    - nonce: 12 bytes (random nonce for AES-GCM)
    - tag: 16 bytes (GCM authentication tag)
    - ciphertext: variable length (encrypted data)
    """

    magic: bytes  # 10 bytes
    salt: bytes  # 16 bytes
    nonce: bytes  # 12 bytes
    tag: bytes  # 16 bytes
    ciphertext: bytes  # variable length

    @classmethod
    def from_bytes(cls, data: bytes) -> "Envelope":
        """
        Parse an envelope from raw bytes.

        Args:
            data: Raw bytes containing the encrypted envelope

        Returns:
            Parsed Envelope object

        Raises:
            InvalidFileFormatError: If magic header doesn't match or data is too short
        """
        # Check minimum size
        if len(data) < ENVELOPE_HEADER_SIZE:
            raise InvalidFileFormatError(
                f"Data too short: expected at least {ENVELOPE_HEADER_SIZE} bytes, got {len(data)}"
            )

        # Extract magic header
        magic = data[: len(MAGIC_HEADER)]

        # Validate magic header
        if not secure_compare(magic, MAGIC_HEADER):
            raise InvalidFileFormatError(
                f"Invalid magic header: expected {MAGIC_HEADER!r}"
            )

        # Parse remaining fields
        offset = len(MAGIC_HEADER)

        salt = data[offset : offset + SALT_SIZE]
        offset += SALT_SIZE

        nonce = data[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE

        tag = data[offset : offset + TAG_SIZE]
        offset += TAG_SIZE

        ciphertext = data[offset:]

        return cls(magic=magic, salt=salt, nonce=nonce, tag=tag, ciphertext=ciphertext)

    def to_bytes(self) -> bytes:
        """
        Serialize envelope to raw bytes.

        Returns:
            Binary representation of the envelope
        """
        return self.magic + self.salt + self.nonce + self.tag + self.ciphertext


# Asymmetric envelope header size: magic (10) + key_length (2) = 12 bytes minimum
ASYMMETRIC_ENVELOPE_MIN_SIZE: int = len(MAGIC_HEADER_ASYMMETRIC) + 2


@dataclass
class AsymmetricEnvelope:
    """
    Represents a parsed asymmetric encrypted envelope.

    The binary envelope format for asymmetric encryption:
    - magic: 10 bytes (b"SHELLOCKa1")
    - key_length: 2 bytes (length of encrypted key as unsigned short)
    - ephemeral_public_key: 32 bytes (X25519 public key)
    - nonce: 12 bytes (random nonce for AES-GCM)
    - tag: 16 bytes (GCM authentication tag)
    - ciphertext: variable length (encrypted data)
    """

    magic: bytes  # 10 bytes
    ephemeral_public_key: bytes  # 32 bytes (X25519 public key)
    nonce: bytes  # 12 bytes
    tag: bytes  # 16 bytes
    ciphertext: bytes  # variable length

    @classmethod
    def from_bytes(cls, data: bytes) -> "AsymmetricEnvelope":
        """
        Parse an asymmetric envelope from raw bytes.

        Args:
            data: Raw bytes containing the encrypted envelope

        Returns:
            Parsed AsymmetricEnvelope object

        Raises:
            InvalidFileFormatError: If magic header doesn't match or data is malformed
        """
        # Check minimum size: magic (10) + key_length (2) + ephemeral_key (32) + nonce (12) + tag (16) = 72
        min_size = len(MAGIC_HEADER_ASYMMETRIC) + 2 + 32 + NONCE_SIZE + TAG_SIZE
        if len(data) < min_size:
            raise InvalidFileFormatError(
                f"Data too short: expected at least {min_size} bytes, got {len(data)}"
            )

        # Extract and validate magic header
        magic = data[: len(MAGIC_HEADER_ASYMMETRIC)]
        if not secure_compare(magic, MAGIC_HEADER_ASYMMETRIC):
            raise InvalidFileFormatError(
                f"Invalid magic header: expected {MAGIC_HEADER_ASYMMETRIC!r}"
            )

        offset = len(MAGIC_HEADER_ASYMMETRIC)

        # Extract key length (2 bytes, unsigned short, big-endian)
        key_length = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2

        # Validate key length (should be 32 for X25519)
        if key_length != 32:
            raise InvalidFileFormatError(
                f"Invalid ephemeral key length: expected 32, got {key_length}"
            )

        # Extract ephemeral public key
        ephemeral_public_key = data[offset : offset + key_length]
        offset += key_length

        # Extract nonce
        nonce = data[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE

        # Extract tag
        tag = data[offset : offset + TAG_SIZE]
        offset += TAG_SIZE

        # Extract ciphertext (remaining bytes)
        ciphertext = data[offset:]

        return cls(
            magic=magic,
            ephemeral_public_key=ephemeral_public_key,
            nonce=nonce,
            tag=tag,
            ciphertext=ciphertext,
        )

    def to_bytes(self) -> bytes:
        """
        Serialize asymmetric envelope to raw bytes.

        Returns:
            Binary representation of the envelope
        """
        key_length = struct.pack(">H", len(self.ephemeral_public_key))
        return (
            self.magic
            + key_length
            + self.ephemeral_public_key
            + self.nonce
            + self.tag
            + self.ciphertext
        )


def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate an X25519 keypair for asymmetric encryption.

    Returns:
        tuple: (private_key_pem, public_key_pem) as bytes

    Note:
        Uses X25519 for key exchange which is the standard approach
        for hybrid encryption with Curve25519.
    """
    # Generate X25519 private key
    private_key = X25519PrivateKey.generate()

    # Get the public key
    public_key = private_key.public_key()

    # Serialize private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return (private_key_pem, public_key_pem)


def encrypt_bytes_public(plaintext: bytes, public_key_pem: bytes) -> bytes:
    """
    Encrypt plaintext bytes with a public key using hybrid encryption.

    Uses X25519 for key exchange and AES-256-GCM for data encryption.

    Args:
        plaintext: Data to encrypt
        public_key_pem: X25519 public key in PEM format

    Returns:
        Binary envelope containing encrypted data

    Raises:
        InvalidFileFormatError: If public key format is invalid
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        # Load the recipient's public key
        recipient_public_key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(recipient_public_key, X25519PublicKey):
            raise InvalidFileFormatError("Invalid public key type: expected X25519")
    except Exception as e:
        if isinstance(e, InvalidFileFormatError):
            raise
        raise InvalidFileFormatError(f"Invalid public key format: {e}")

    # Generate ephemeral keypair for this encryption
    ephemeral_private_key = X25519PrivateKey.generate()
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Perform X25519 key exchange to derive shared secret
    shared_secret = ephemeral_private_key.exchange(recipient_public_key)

    # Derive symmetric key from shared secret using HKDF
    derived_key = bytearray(
        HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=None,
            info=b"shellock-asymmetric-encryption",
        ).derive(shared_secret)
    )

    try:
        # Generate random nonce
        nonce = secrets.token_bytes(NONCE_SIZE)

        # Encrypt with AES-256-GCM
        aesgcm = AESGCM(bytes(derived_key))
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

        # Split ciphertext and tag
        ciphertext = ciphertext_with_tag[:-TAG_SIZE]
        tag = ciphertext_with_tag[-TAG_SIZE:]

        # Get ephemeral public key bytes (raw format)
        ephemeral_public_key_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        # Create and serialize envelope
        envelope = AsymmetricEnvelope(
            magic=MAGIC_HEADER_ASYMMETRIC,
            ephemeral_public_key=ephemeral_public_key_bytes,
            nonce=nonce,
            tag=tag,
            ciphertext=ciphertext,
        )

        return envelope.to_bytes()
    finally:
        # Securely cleanup derived key
        _secure_cleanup(derived_key)


def decrypt_bytes_private(
    blob: bytes, private_key_pem: bytes, passphrase: Optional[str] = None
) -> bytes:
    """
    Decrypt an encrypted envelope with a private key.

    Args:
        blob: Binary envelope from encrypt_bytes_public
        private_key_pem: X25519 private key in PEM format
        passphrase: Optional passphrase if private key is encrypted

    Returns:
        Original plaintext bytes

    Raises:
        InvalidFileFormatError: If magic header doesn't match or envelope is malformed
        AuthenticationError: If private key is wrong or data is tampered
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Parse envelope
    envelope = AsymmetricEnvelope.from_bytes(blob)

    # Load private key
    try:
        password = passphrase.encode("utf-8") if passphrase else None
        private_key = serialization.load_pem_private_key(
            private_key_pem, password=password
        )
        if not isinstance(private_key, X25519PrivateKey):
            raise InvalidFileFormatError("Invalid private key type: expected X25519")
    except Exception as e:
        if isinstance(e, InvalidFileFormatError):
            raise
        raise InvalidFileFormatError(f"Invalid private key format: {e}")

    # Reconstruct ephemeral public key from raw bytes
    try:
        ephemeral_public_key = X25519PublicKey.from_public_bytes(
            envelope.ephemeral_public_key
        )
    except Exception as e:
        raise InvalidFileFormatError(f"Invalid ephemeral public key: {e}")

    # Perform X25519 key exchange to derive shared secret
    shared_secret = private_key.exchange(ephemeral_public_key)

    # Derive symmetric key from shared secret using HKDF
    derived_key = bytearray(
        HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=None,
            info=b"shellock-asymmetric-encryption",
        ).derive(shared_secret)
    )

    try:
        # Create AES-GCM cipher
        aesgcm = AESGCM(bytes(derived_key))

        # AES-GCM decrypt expects ciphertext + tag concatenated
        ciphertext_with_tag = envelope.ciphertext + envelope.tag

        try:
            # Decrypt and verify authentication tag
            plaintext = aesgcm.decrypt(envelope.nonce, ciphertext_with_tag, None)
            return plaintext
        except InvalidTag:
            # Use generic error message to prevent information leakage
            raise AuthenticationError("Authentication failed")
    finally:
        # Securely cleanup derived key
        _secure_cleanup(derived_key)


def encrypt_bytes_key(plaintext: bytes, symmetric_key: bytes) -> bytes:
    """
    Encrypt plaintext bytes with a pre-generated symmetric key.

    Uses the same envelope format as passphrase-based encryption but skips
    the KDF step, using the provided key directly for AES-256-GCM encryption.

    Args:
        plaintext: Data to encrypt
        symmetric_key: 32-byte symmetric key for direct use

    Returns:
        Binary envelope containing: magic header + salt (zeros) + nonce + tag + ciphertext

    Raises:
        ValueError: If symmetric_key is not 32 bytes
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Validate key size
    if len(symmetric_key) != KEY_SIZE:
        raise ValueError(
            f"Symmetric key must be {KEY_SIZE} bytes, got {len(symmetric_key)}"
        )

    # Generate random nonce (salt is not used for direct key encryption)
    nonce = secrets.token_bytes(NONCE_SIZE)

    # For symmetric key-based encryption, we use a zero salt as a placeholder
    # since no key derivation is performed
    salt = b"\x00" * SALT_SIZE

    # Create mutable bytearray for key to enable secure cleanup
    key_array = bytearray(symmetric_key)

    try:
        # Create AES-GCM cipher and encrypt
        aesgcm = AESGCM(bytes(key_array))

        # AES-GCM encrypt returns ciphertext + tag concatenated
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

        # Split ciphertext and tag (tag is last 16 bytes)
        ciphertext = ciphertext_with_tag[:-TAG_SIZE]
        tag = ciphertext_with_tag[-TAG_SIZE:]

        # Create and serialize envelope
        envelope = Envelope(
            magic=MAGIC_HEADER, salt=salt, nonce=nonce, tag=tag, ciphertext=ciphertext
        )

        return envelope.to_bytes()
    finally:
        # Securely cleanup key from memory
        _secure_cleanup(key_array)


def decrypt_bytes_key(blob: bytes, symmetric_key: bytes) -> bytes:
    """
    Decrypt an encrypted envelope with a symmetric key.

    Uses the same envelope format as passphrase-based encryption but skips
    the KDF step, using the provided key directly for AES-256-GCM decryption.

    Args:
        blob: Binary envelope from encrypt_bytes_key
        symmetric_key: 32-byte symmetric key for direct use

    Returns:
        Original plaintext bytes

    Raises:
        ValueError: If symmetric_key is not 32 bytes
        InvalidFileFormatError: If magic header doesn't match or envelope is malformed
        AuthenticationError: If key is wrong or data is tampered
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Validate key size
    if len(symmetric_key) != KEY_SIZE:
        raise ValueError(
            f"Symmetric key must be {KEY_SIZE} bytes, got {len(symmetric_key)}"
        )

    # Parse envelope - this will raise InvalidFileFormatError if format is invalid
    envelope = Envelope.from_bytes(blob)

    # Create mutable bytearray for key to enable secure cleanup
    key_array = bytearray(symmetric_key)

    try:
        # Create AES-GCM cipher
        aesgcm = AESGCM(bytes(key_array))

        # AES-GCM decrypt expects ciphertext + tag concatenated
        ciphertext_with_tag = envelope.ciphertext + envelope.tag

        try:
            # Decrypt and verify authentication tag
            plaintext = aesgcm.decrypt(envelope.nonce, ciphertext_with_tag, None)
            return plaintext
        except InvalidTag:
            # Use generic error message to prevent information leakage
            raise AuthenticationError("Authentication failed")
    finally:
        # Securely cleanup key from memory
        _secure_cleanup(key_array)
