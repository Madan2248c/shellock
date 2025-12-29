"""
Tests for the CLI module.

This module contains tests for the command-line interface.
"""

import base64
import os
import sys
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from shellock.cli import cli
from shellock.crypto import KEY_SIZE, generate_keypair

# Skip permission tests on Windows (Unix permissions not supported)
skip_on_windows = pytest.mark.skipif(
    sys.platform == "win32", reason="Unix file permissions not supported on Windows"
)


@pytest.fixture
def runner() -> CliRunner:
    """Create a Click test runner."""
    return CliRunner()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


class TestCLIHelp:
    """Tests for CLI help output."""

    def test_main_help(self, runner: CliRunner) -> None:
        """
        Test that main --help displays usage information.

        **Validates: Requirements 12.1**
        """
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Shellock - Secure encryption" in result.output
        assert "encrypt" in result.output
        assert "decrypt" in result.output
        assert "generate-key" in result.output

    def test_encrypt_help(self, runner: CliRunner) -> None:
        """
        Test that encrypt --help displays usage information.

        **Validates: Requirements 12.2**
        """
        result = runner.invoke(cli, ["encrypt", "--help"])
        assert result.exit_code == 0
        assert "Encrypt a file with a passphrase" in result.output
        assert "--out" in result.output
        assert "--passphrase" in result.output

    def test_decrypt_help(self, runner: CliRunner) -> None:
        """
        Test that decrypt --help displays usage information.

        **Validates: Requirements 12.3**
        """
        result = runner.invoke(cli, ["decrypt", "--help"])
        assert result.exit_code == 0
        assert "Decrypt a file with a passphrase" in result.output
        assert "--out" in result.output
        assert "--passphrase" in result.output

    def test_generate_key_help(self, runner: CliRunner) -> None:
        """
        Test that generate-key --help displays usage information.

        **Validates: Requirements 12.4**
        """
        result = runner.invoke(cli, ["generate-key", "--help"])
        assert result.exit_code == 0
        assert "Generate a random encryption key" in result.output
        assert "--type" in result.output
        assert "symmetric" in result.output
        assert "asymmetric" in result.output

    def test_encrypt_public_help(self, runner: CliRunner) -> None:
        """
        Test that encrypt-public --help displays usage information.

        **Validates: Requirements 12.5**
        """
        result = runner.invoke(cli, ["encrypt-public", "--help"])
        assert result.exit_code == 0
        assert "Encrypt a file with a public key" in result.output
        assert "--key" in result.output
        assert "--out" in result.output

    def test_decrypt_private_help(self, runner: CliRunner) -> None:
        """
        Test that decrypt-private --help displays usage information.

        **Validates: Requirements 12.6**
        """
        result = runner.invoke(cli, ["decrypt-private", "--help"])
        assert result.exit_code == 0
        assert "Decrypt a file with a private key" in result.output
        assert "--key" in result.output
        assert "--out" in result.output

    def test_encrypt_key_help(self, runner: CliRunner) -> None:
        """
        Test that encrypt-key --help displays usage information.

        **Validates: Requirements 12.7**
        """
        result = runner.invoke(cli, ["encrypt-key", "--help"])
        assert result.exit_code == 0
        assert "Encrypt a file with a symmetric key" in result.output
        assert "--key" in result.output
        assert "--out" in result.output

    def test_decrypt_key_help(self, runner: CliRunner) -> None:
        """
        Test that decrypt-key --help displays usage information.

        **Validates: Requirements 12.8**
        """
        result = runner.invoke(cli, ["decrypt-key", "--help"])
        assert result.exit_code == 0
        assert "Decrypt a file with a symmetric key" in result.output
        assert "--key" in result.output
        assert "--out" in result.output


class TestPassphraseEncryptDecrypt:
    """Tests for passphrase-based encrypt/decrypt commands."""

    def test_encrypt_decrypt_round_trip(self, runner: CliRunner, temp_dir: str) -> None:
        """
        Test encrypt and decrypt round trip via CLI.

        **Validates: Requirements 6.1, 6.4, 7.1, 7.5**
        """
        input_path = os.path.join(temp_dir, "input.txt")
        encrypted_path = os.path.join(temp_dir, "encrypted.bin")
        decrypted_path = os.path.join(temp_dir, "decrypted.txt")

        original_content = b"Test content for encryption"
        Path(input_path).write_bytes(original_content)

        # Encrypt
        result = runner.invoke(
            cli,
            [
                "encrypt",
                input_path,
                "--out",
                encrypted_path,
                "--passphrase",
                "test-passphrase",
            ],
        )
        assert result.exit_code == 0
        assert "Encrypted" in result.output

        # Decrypt
        result = runner.invoke(
            cli,
            [
                "decrypt",
                encrypted_path,
                "--out",
                decrypted_path,
                "--passphrase",
                "test-passphrase",
            ],
        )
        assert result.exit_code == 0
        assert "Decrypted" in result.output

        # Verify content
        decrypted_content = Path(decrypted_path).read_bytes()
        assert decrypted_content == original_content

    def test_encrypt_file_not_found(self, runner: CliRunner, temp_dir: str) -> None:
        """
        Test that encrypt exits with error for missing input file.

        **Validates: Requirements 6.3**
        """
        nonexistent = os.path.join(temp_dir, "nonexistent.txt")
        output = os.path.join(temp_dir, "output.bin")

        result = runner.invoke(
            cli, ["encrypt", nonexistent, "--out", output, "--passphrase", "test"]
        )
        assert result.exit_code != 0

    def test_decrypt_wrong_passphrase(self, runner: CliRunner, temp_dir: str) -> None:
        """
        Test that decrypt exits with error for wrong passphrase.

        **Validates: Requirements 7.3**
        """
        input_path = os.path.join(temp_dir, "input.txt")
        encrypted_path = os.path.join(temp_dir, "encrypted.bin")
        decrypted_path = os.path.join(temp_dir, "decrypted.txt")

        Path(input_path).write_bytes(b"Test content")

        # Encrypt with correct passphrase
        runner.invoke(
            cli,
            [
                "encrypt",
                input_path,
                "--out",
                encrypted_path,
                "--passphrase",
                "correct-passphrase",
            ],
        )

        # Decrypt with wrong passphrase
        result = runner.invoke(
            cli,
            [
                "decrypt",
                encrypted_path,
                "--out",
                decrypted_path,
                "--passphrase",
                "wrong-passphrase",
            ],
        )
        assert result.exit_code != 0
        assert "Authentication failed" in result.output

    def test_decrypt_invalid_file_format(
        self, runner: CliRunner, temp_dir: str
    ) -> None:
        """
        Test that decrypt exits with error for invalid file format.

        **Validates: Requirements 7.4**
        """
        invalid_file = os.path.join(temp_dir, "invalid.bin")
        output = os.path.join(temp_dir, "output.txt")

        Path(invalid_file).write_bytes(b"not a valid encrypted file")

        result = runner.invoke(
            cli, ["decrypt", invalid_file, "--out", output, "--passphrase", "test"]
        )
        assert result.exit_code != 0
        assert "Invalid file format" in result.output


class TestGenerateKey:
    """Tests for generate-key command."""

    def test_generate_symmetric_key(self, runner: CliRunner, temp_dir: str) -> None:
        """
        Test generating a symmetric key.

        **Validates: Requirements 8.1, 8.3**
        """
        key_path = os.path.join(temp_dir, "secret.key")

        result = runner.invoke(
            cli,
            [
                "generate-key",
                "--type",
                "symmetric",
                "--out",
                key_path,
                "--yes",  # Skip confirmation
            ],
        )
        assert result.exit_code == 0
        assert "Symmetric key generated" in result.output

        # Verify key file exists and is valid base64
        assert os.path.exists(key_path)
        key_content = Path(key_path).read_text()
        key_bytes = base64.b64decode(key_content)
        assert len(key_bytes) == KEY_SIZE

    @skip_on_windows
    def test_generate_symmetric_key_permissions(
        self, runner: CliRunner, temp_dir: str
    ) -> None:
        """
        Test that generated symmetric key has secure permissions (600).

        **Validates: Requirements 8.3**
        """
        key_path = os.path.join(temp_dir, "secret.key")

        runner.invoke(
            cli, ["generate-key", "--type", "symmetric", "--out", key_path, "--yes"]
        )

        # Check permissions
        file_stat = os.stat(key_path)
        permissions = file_stat.st_mode & 0o777
        assert permissions == 0o600

    def test_generate_asymmetric_key(self, runner: CliRunner, temp_dir: str) -> None:
        """
        Test generating an asymmetric keypair.

        **Validates: Requirements 8.2, 8.4**
        """
        private_key_path = os.path.join(temp_dir, "private.pem")

        result = runner.invoke(
            cli,
            [
                "generate-key",
                "--type",
                "asymmetric",
                "--out",
                private_key_path,
                "--yes",
            ],
        )
        assert result.exit_code == 0
        assert "Keypair generated" in result.output
        assert "Public key" in result.output

        # Verify private key file exists and is valid PEM
        assert os.path.exists(private_key_path)
        private_key_content = Path(private_key_path).read_bytes()
        assert b"-----BEGIN PRIVATE KEY-----" in private_key_content

    @skip_on_windows
    def test_generate_asymmetric_key_permissions(
        self, runner: CliRunner, temp_dir: str
    ) -> None:
        """
        Test that generated private key has secure permissions (600).

        **Validates: Requirements 8.4**
        """
        private_key_path = os.path.join(temp_dir, "private.pem")

        runner.invoke(
            cli,
            [
                "generate-key",
                "--type",
                "asymmetric",
                "--out",
                private_key_path,
                "--yes",
            ],
        )

        # Check permissions
        file_stat = os.stat(private_key_path)
        permissions = file_stat.st_mode & 0o777
        assert permissions == 0o600


class TestAsymmetricEncryptDecrypt:
    """Tests for asymmetric encrypt/decrypt commands."""

    def test_encrypt_public_decrypt_private_round_trip(
        self, runner: CliRunner, temp_dir: str
    ) -> None:
        """
        Test encrypt-public and decrypt-private round trip.

        **Validates: Requirements 9.1, 9.4**
        """
        input_path = os.path.join(temp_dir, "input.txt")
        encrypted_path = os.path.join(temp_dir, "encrypted.bin")
        decrypted_path = os.path.join(temp_dir, "decrypted.txt")
        private_key_path = os.path.join(temp_dir, "private.pem")
        public_key_path = os.path.join(temp_dir, "public.pem")

        original_content = b"Test content for asymmetric encryption"
        Path(input_path).write_bytes(original_content)

        # Generate keypair
        private_key_pem, public_key_pem = generate_keypair()
        Path(private_key_path).write_bytes(private_key_pem)
        Path(public_key_path).write_bytes(public_key_pem)

        # Encrypt with public key
        result = runner.invoke(
            cli,
            [
                "encrypt-public",
                input_path,
                "--key",
                public_key_path,
                "--out",
                encrypted_path,
            ],
        )
        assert result.exit_code == 0
        assert "Encrypted" in result.output

        # Decrypt with private key (provide empty passphrase via --passphrase)
        result = runner.invoke(
            cli,
            [
                "decrypt-private",
                encrypted_path,
                "--key",
                private_key_path,
                "--out",
                decrypted_path,
                "--passphrase",
                "",  # Empty passphrase for unencrypted key
            ],
        )
        assert result.exit_code == 0
        assert "Decrypted" in result.output

        # Verify content
        decrypted_content = Path(decrypted_path).read_bytes()
        assert decrypted_content == original_content

    def test_encrypt_public_invalid_key(self, runner: CliRunner, temp_dir: str) -> None:
        """
        Test that encrypt-public exits with error for invalid key.

        **Validates: Requirements 9.1**
        """
        input_path = os.path.join(temp_dir, "input.txt")
        encrypted_path = os.path.join(temp_dir, "encrypted.bin")
        invalid_key_path = os.path.join(temp_dir, "invalid.pem")

        Path(input_path).write_bytes(b"Test content")
        Path(invalid_key_path).write_bytes(b"not a valid key")

        result = runner.invoke(
            cli,
            [
                "encrypt-public",
                input_path,
                "--key",
                invalid_key_path,
                "--out",
                encrypted_path,
            ],
        )
        assert result.exit_code != 0
        assert "Invalid key format" in result.output


class TestSymmetricKeyEncryptDecrypt:
    """Tests for symmetric key-based encrypt/decrypt commands."""

    def test_encrypt_key_decrypt_key_round_trip(
        self, runner: CliRunner, temp_dir: str
    ) -> None:
        """
        Test encrypt-key and decrypt-key round trip.

        **Validates: Requirements 11.1, 11.2**
        """
        input_path = os.path.join(temp_dir, "input.txt")
        encrypted_path = os.path.join(temp_dir, "encrypted.bin")
        decrypted_path = os.path.join(temp_dir, "decrypted.txt")
        key_path = os.path.join(temp_dir, "secret.key")

        original_content = b"Test content for symmetric key encryption"
        Path(input_path).write_bytes(original_content)

        # Generate symmetric key
        key = os.urandom(KEY_SIZE)
        key_b64 = base64.b64encode(key).decode()
        Path(key_path).write_text(key_b64)

        # Encrypt with symmetric key
        result = runner.invoke(
            cli, ["encrypt-key", input_path, "--key", key_path, "--out", encrypted_path]
        )
        assert result.exit_code == 0
        assert "Encrypted" in result.output

        # Decrypt with symmetric key
        result = runner.invoke(
            cli,
            ["decrypt-key", encrypted_path, "--key", key_path, "--out", decrypted_path],
        )
        assert result.exit_code == 0
        assert "Decrypted" in result.output

        # Verify content
        decrypted_content = Path(decrypted_path).read_bytes()
        assert decrypted_content == original_content

    def test_encrypt_key_invalid_key_format(
        self, runner: CliRunner, temp_dir: str
    ) -> None:
        """
        Test that encrypt-key exits with error for invalid key format.

        **Validates: Requirements 11.5**
        """
        input_path = os.path.join(temp_dir, "input.txt")
        encrypted_path = os.path.join(temp_dir, "encrypted.bin")
        invalid_key_path = os.path.join(temp_dir, "invalid.key")

        Path(input_path).write_bytes(b"Test content")
        Path(invalid_key_path).write_text("not valid base64!!!")

        result = runner.invoke(
            cli,
            [
                "encrypt-key",
                input_path,
                "--key",
                invalid_key_path,
                "--out",
                encrypted_path,
            ],
        )
        assert result.exit_code != 0
        assert "Invalid key format" in result.output

    def test_decrypt_key_wrong_key(self, runner: CliRunner, temp_dir: str) -> None:
        """
        Test that decrypt-key exits with error for wrong key.

        **Validates: Requirements 11.2**
        """
        input_path = os.path.join(temp_dir, "input.txt")
        encrypted_path = os.path.join(temp_dir, "encrypted.bin")
        decrypted_path = os.path.join(temp_dir, "decrypted.txt")
        correct_key_path = os.path.join(temp_dir, "correct.key")
        wrong_key_path = os.path.join(temp_dir, "wrong.key")

        Path(input_path).write_bytes(b"Test content")

        # Create two different keys
        correct_key = base64.b64encode(os.urandom(KEY_SIZE)).decode()
        wrong_key = base64.b64encode(os.urandom(KEY_SIZE)).decode()
        Path(correct_key_path).write_text(correct_key)
        Path(wrong_key_path).write_text(wrong_key)

        # Encrypt with correct key
        runner.invoke(
            cli,
            [
                "encrypt-key",
                input_path,
                "--key",
                correct_key_path,
                "--out",
                encrypted_path,
            ],
        )

        # Decrypt with wrong key
        result = runner.invoke(
            cli,
            [
                "decrypt-key",
                encrypted_path,
                "--key",
                wrong_key_path,
                "--out",
                decrypted_path,
            ],
        )
        assert result.exit_code != 0
        assert "Authentication failed" in result.output


class TestCLIVersion:
    """Tests for CLI version output."""

    def test_version_option(self, runner: CliRunner) -> None:
        """Test that --version displays version information."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output or "version" in result.output.lower()
