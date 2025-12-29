"""
Tests for the file-based API module.

This module contains unit tests for file encryption and decryption operations.
"""

import base64
import os
import sys
import tempfile
from pathlib import Path

import pytest

from shellock.api import (
    decrypt_file,
    decrypt_file_key,
    decrypt_file_private,
    encrypt_file,
    encrypt_file_key,
    encrypt_file_public,
)
from shellock.crypto import KEY_SIZE, generate_keypair
from shellock.exceptions import AuthenticationError, InvalidFileFormatError

# Skip permission tests on Windows (Unix permissions not supported)
skip_on_windows = pytest.mark.skipif(
    sys.platform == "win32", reason="Unix file permissions not supported on Windows"
)


class TestPassphraseFileEncryption:
    """Tests for passphrase-based file encryption and decryption."""

    def test_encrypt_decrypt_file_round_trip(self) -> None:
        """
        Test encrypt_file and decrypt_file round trip with temp files.

        **Validates: Requirements 5.1, 5.2**
        """
        passphrase = "test-passphrase-123"
        original_content = b"This is test content for encryption."

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")

            # Write original content
            Path(input_path).write_bytes(original_content)

            # Encrypt
            encrypt_file(input_path, encrypted_path, passphrase)

            # Verify encrypted file exists and is different from original
            assert os.path.exists(encrypted_path)
            encrypted_content = Path(encrypted_path).read_bytes()
            assert encrypted_content != original_content

            # Decrypt
            decrypt_file(encrypted_path, decrypted_path, passphrase)

            # Verify decrypted content matches original
            decrypted_content = Path(decrypted_path).read_bytes()
            assert decrypted_content == original_content

    @skip_on_windows
    def test_encrypt_file_sets_secure_permissions(self) -> None:
        """
        Test that encrypt_file sets secure file permissions (600).

        **Validates: Requirements 5.3**
        """
        passphrase = "test-passphrase"  # noqa: S105
        original_content = b"Test content"

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")

            Path(input_path).write_bytes(original_content)
            encrypt_file(input_path, encrypted_path, passphrase)

            # Check file permissions (should be 600 = owner read/write only)
            file_stat = os.stat(encrypted_path)
            permissions = file_stat.st_mode & 0o777
            assert permissions == 0o600

    @skip_on_windows
    def test_decrypt_file_sets_secure_permissions(self) -> None:
        """
        Test that decrypt_file sets secure file permissions (600).

        **Validates: Requirements 5.3**
        """
        passphrase = "test-passphrase"  # noqa: S105
        original_content = b"Test content"

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")

            Path(input_path).write_bytes(original_content)
            encrypt_file(input_path, encrypted_path, passphrase)
            decrypt_file(encrypted_path, decrypted_path, passphrase)

            # Check file permissions (should be 600 = owner read/write only)
            file_stat = os.stat(decrypted_path)
            permissions = file_stat.st_mode & 0o777
            assert permissions == 0o600

    def test_encrypt_file_not_found(self) -> None:
        """
        Test that encrypt_file raises FileNotFoundError for missing input file.

        **Validates: Requirements 5.3**
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            nonexistent_path = os.path.join(tmpdir, "nonexistent.txt")
            output_path = os.path.join(tmpdir, "output.bin")

            with pytest.raises(FileNotFoundError, match="File not found"):
                encrypt_file(nonexistent_path, output_path, "passphrase")

    def test_decrypt_file_not_found(self) -> None:
        """
        Test that decrypt_file raises FileNotFoundError for missing input file.

        **Validates: Requirements 5.3**
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            nonexistent_path = os.path.join(tmpdir, "nonexistent.bin")
            output_path = os.path.join(tmpdir, "output.txt")

            with pytest.raises(FileNotFoundError, match="File not found"):
                decrypt_file(nonexistent_path, output_path, "passphrase")

    def test_encrypt_file_output_dir_not_found(self) -> None:
        """
        Test that encrypt_file raises FileNotFoundError for missing output directory.

        **Validates: Requirements 5.4**
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            output_path = os.path.join(tmpdir, "nonexistent_dir", "output.bin")

            Path(input_path).write_bytes(b"test content")

            with pytest.raises(FileNotFoundError, match="Directory not found"):
                encrypt_file(input_path, output_path, "passphrase")

    def test_decrypt_file_wrong_passphrase(self) -> None:
        """
        Test that decrypt_file raises AuthenticationError for wrong passphrase.

        **Validates: Requirements 5.2**
        """
        original_content = b"Test content"

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")

            Path(input_path).write_bytes(original_content)
            encrypt_file(input_path, encrypted_path, "correct-passphrase")

            with pytest.raises(AuthenticationError, match="Authentication failed"):
                decrypt_file(encrypted_path, decrypted_path, "wrong-passphrase")

    def test_encrypt_decrypt_empty_file(self) -> None:
        """Test encryption and decryption of empty files."""
        passphrase = "test-passphrase"

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "empty.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")

            # Create empty file
            Path(input_path).write_bytes(b"")

            # Encrypt and decrypt
            encrypt_file(input_path, encrypted_path, passphrase)
            decrypt_file(encrypted_path, decrypted_path, passphrase)

            # Verify empty content
            assert Path(decrypted_path).read_bytes() == b""


class TestAsymmetricFileEncryption:
    """Tests for asymmetric file encryption and decryption."""

    def test_encrypt_decrypt_file_public_private_round_trip(self) -> None:
        """
        Test encrypt_file_public and decrypt_file_private round trip.

        **Validates: Requirements 9.1, 9.4**
        """
        original_content = b"This is test content for asymmetric encryption."

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")
            private_key_path = os.path.join(tmpdir, "private.pem")
            public_key_path = os.path.join(tmpdir, "public.pem")

            # Generate keypair and save to files
            private_key_pem, public_key_pem = generate_keypair()
            Path(private_key_path).write_bytes(private_key_pem)
            Path(public_key_path).write_bytes(public_key_pem)

            # Write original content
            Path(input_path).write_bytes(original_content)

            # Encrypt with public key
            encrypt_file_public(input_path, encrypted_path, public_key_path)

            # Verify encrypted file exists and is different from original
            assert os.path.exists(encrypted_path)
            encrypted_content = Path(encrypted_path).read_bytes()
            assert encrypted_content != original_content

            # Decrypt with private key
            decrypt_file_private(encrypted_path, decrypted_path, private_key_path)

            # Verify decrypted content matches original
            decrypted_content = Path(decrypted_path).read_bytes()
            assert decrypted_content == original_content

    def test_encrypt_file_public_key_not_found(self) -> None:
        """
        Test that encrypt_file_public raises FileNotFoundError for missing public key.

        **Validates: Requirements 9.1**
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            nonexistent_key = os.path.join(tmpdir, "nonexistent.pem")

            Path(input_path).write_bytes(b"test content")

            with pytest.raises(FileNotFoundError, match="File not found"):
                encrypt_file_public(input_path, encrypted_path, nonexistent_key)

    def test_decrypt_file_private_key_not_found(self) -> None:
        """
        Test that decrypt_file_private raises FileNotFoundError for missing private key.

        **Validates: Requirements 9.4**
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a valid encrypted file first
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")
            public_key_path = os.path.join(tmpdir, "public.pem")
            nonexistent_key = os.path.join(tmpdir, "nonexistent.pem")

            private_key_pem, public_key_pem = generate_keypair()
            Path(public_key_path).write_bytes(public_key_pem)
            Path(input_path).write_bytes(b"test content")

            encrypt_file_public(input_path, encrypted_path, public_key_path)

            with pytest.raises(FileNotFoundError, match="File not found"):
                decrypt_file_private(encrypted_path, decrypted_path, nonexistent_key)

    def test_encrypt_file_public_invalid_key_format(self) -> None:
        """
        Test that encrypt_file_public raises InvalidFileFormatError for invalid key.

        **Validates: Requirements 9.1**
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            invalid_key_path = os.path.join(tmpdir, "invalid.pem")

            Path(input_path).write_bytes(b"test content")
            Path(invalid_key_path).write_bytes(b"not a valid PEM key")

            with pytest.raises(
                InvalidFileFormatError, match="Invalid public key format"
            ):
                encrypt_file_public(input_path, encrypted_path, invalid_key_path)

    def test_decrypt_file_private_wrong_key(self) -> None:
        """
        Test that decrypt_file_private raises AuthenticationError for wrong key.

        **Validates: Requirements 9.4**
        """
        original_content = b"Test content"

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")
            public_key_path = os.path.join(tmpdir, "public.pem")
            wrong_private_key_path = os.path.join(tmpdir, "wrong_private.pem")

            # Generate two different keypairs
            private_key1_pem, public_key1_pem = generate_keypair()
            private_key2_pem, _ = generate_keypair()

            Path(public_key_path).write_bytes(public_key1_pem)
            Path(wrong_private_key_path).write_bytes(private_key2_pem)
            Path(input_path).write_bytes(original_content)

            # Encrypt with first public key
            encrypt_file_public(input_path, encrypted_path, public_key_path)

            # Try to decrypt with second private key
            with pytest.raises(AuthenticationError, match="Authentication failed"):
                decrypt_file_private(
                    encrypted_path, decrypted_path, wrong_private_key_path
                )


class TestSymmetricKeyFileEncryption:
    """Tests for symmetric key-based file encryption and decryption."""

    def test_encrypt_decrypt_file_key_round_trip(self) -> None:
        """
        Test encrypt_file_key and decrypt_file_key round trip.

        **Validates: Requirements 11.1, 11.2**
        """
        original_content = b"This is test content for symmetric key encryption."

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")
            key_path = os.path.join(tmpdir, "key.txt")

            # Generate and save symmetric key (base64 encoded)
            symmetric_key = os.urandom(KEY_SIZE)
            key_b64 = base64.b64encode(symmetric_key).decode()
            Path(key_path).write_text(key_b64)

            # Write original content
            Path(input_path).write_bytes(original_content)

            # Encrypt with symmetric key
            encrypt_file_key(input_path, encrypted_path, key_path)

            # Verify encrypted file exists and is different from original
            assert os.path.exists(encrypted_path)
            encrypted_content = Path(encrypted_path).read_bytes()
            assert encrypted_content != original_content

            # Decrypt with symmetric key
            decrypt_file_key(encrypted_path, decrypted_path, key_path)

            # Verify decrypted content matches original
            decrypted_content = Path(decrypted_path).read_bytes()
            assert decrypted_content == original_content

    def test_encrypt_file_key_not_found(self) -> None:
        """
        Test that encrypt_file_key raises FileNotFoundError for missing key file.

        **Validates: Requirements 11.3, 11.4**
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            nonexistent_key = os.path.join(tmpdir, "nonexistent.key")

            Path(input_path).write_bytes(b"test content")

            with pytest.raises(FileNotFoundError, match="File not found"):
                encrypt_file_key(input_path, encrypted_path, nonexistent_key)

    def test_decrypt_file_key_not_found(self) -> None:
        """
        Test that decrypt_file_key raises FileNotFoundError for missing key file.

        **Validates: Requirements 11.3, 11.4**
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a valid encrypted file first
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")
            key_path = os.path.join(tmpdir, "key.txt")
            nonexistent_key = os.path.join(tmpdir, "nonexistent.key")

            symmetric_key = os.urandom(KEY_SIZE)
            key_b64 = base64.b64encode(symmetric_key).decode()
            Path(key_path).write_text(key_b64)
            Path(input_path).write_bytes(b"test content")

            encrypt_file_key(input_path, encrypted_path, key_path)

            with pytest.raises(FileNotFoundError, match="File not found"):
                decrypt_file_key(encrypted_path, decrypted_path, nonexistent_key)

    def test_encrypt_file_key_invalid_format(self) -> None:
        """
        Test that encrypt_file_key raises InvalidFileFormatError for invalid key format.

        **Validates: Requirements 11.3, 11.4**
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            invalid_key_path = os.path.join(tmpdir, "invalid.key")

            Path(input_path).write_bytes(b"test content")
            Path(invalid_key_path).write_text("not valid base64!!!")

            with pytest.raises(InvalidFileFormatError, match="Invalid key file format"):
                encrypt_file_key(input_path, encrypted_path, invalid_key_path)

    def test_encrypt_file_key_wrong_size(self) -> None:
        """
        Test that encrypt_file_key raises InvalidFileFormatError for wrong key size.

        **Validates: Requirements 11.3, 11.4**
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            wrong_size_key_path = os.path.join(tmpdir, "wrong_size.key")

            Path(input_path).write_bytes(b"test content")
            # Create a key with wrong size (16 bytes instead of 32)
            wrong_key = base64.b64encode(os.urandom(16)).decode()
            Path(wrong_size_key_path).write_text(wrong_key)

            with pytest.raises(InvalidFileFormatError, match="Invalid key size"):
                encrypt_file_key(input_path, encrypted_path, wrong_size_key_path)

    def test_decrypt_file_key_wrong_key(self) -> None:
        """
        Test that decrypt_file_key raises AuthenticationError for wrong key.

        **Validates: Requirements 11.1, 11.2**
        """
        original_content = b"Test content"

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")
            correct_key_path = os.path.join(tmpdir, "correct.key")
            wrong_key_path = os.path.join(tmpdir, "wrong.key")

            # Create two different keys
            correct_key = base64.b64encode(os.urandom(KEY_SIZE)).decode()
            wrong_key = base64.b64encode(os.urandom(KEY_SIZE)).decode()

            Path(correct_key_path).write_text(correct_key)
            Path(wrong_key_path).write_text(wrong_key)
            Path(input_path).write_bytes(original_content)

            # Encrypt with correct key
            encrypt_file_key(input_path, encrypted_path, correct_key_path)

            # Try to decrypt with wrong key
            with pytest.raises(AuthenticationError, match="Authentication failed"):
                decrypt_file_key(encrypted_path, decrypted_path, wrong_key_path)

    def test_symmetric_key_file_with_whitespace(self) -> None:
        """Test that key files with whitespace are handled correctly."""
        original_content = b"Test content"

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            decrypted_path = os.path.join(tmpdir, "decrypted.txt")
            key_path = os.path.join(tmpdir, "key.txt")

            # Create key with leading/trailing whitespace and newlines
            symmetric_key = os.urandom(KEY_SIZE)
            key_b64 = base64.b64encode(symmetric_key).decode()
            Path(key_path).write_text(f"  \n{key_b64}\n  ")

            Path(input_path).write_bytes(original_content)

            # Should work despite whitespace
            encrypt_file_key(input_path, encrypted_path, key_path)
            decrypt_file_key(encrypted_path, decrypted_path, key_path)

            assert Path(decrypted_path).read_bytes() == original_content
