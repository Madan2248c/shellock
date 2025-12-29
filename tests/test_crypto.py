"""
Tests for the crypto module.

This module contains unit tests and property-based tests for cryptographic operations.
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from shellock.crypto import (
    ENVELOPE_HEADER_SIZE,
    KEY_SIZE,
    MAGIC_HEADER,
    NONCE_SIZE,
    SALT_SIZE,
    TAG_SIZE,
    Envelope,
    decrypt_bytes,
    decrypt_bytes_key,
    decrypt_bytes_private,
    derive_key_from_passphrase,
    encrypt_bytes,
    encrypt_bytes_key,
    encrypt_bytes_public,
    generate_keypair,
)
from shellock.exceptions import AuthenticationError, InvalidFileFormatError


class TestKeyDerivation:
    """Tests for key derivation functions."""

    @pytest.mark.property
    @settings(deadline=5000)  # Allow 5 seconds for Argon2id computation
    @given(
        passphrase=st.text(min_size=1, max_size=100),
        salt=st.binary(min_size=SALT_SIZE, max_size=SALT_SIZE),
    )
    def test_key_derivation_determinism(self, passphrase: str, salt: bytes) -> None:
        """
        Property 1: Key Derivation Determinism

        For any passphrase and salt combination, calling derive_key_from_passphrase
        multiple times SHALL produce the same 32-byte key.

        **Feature: shellock, Property 1: Key Derivation Determinism**
        **Validates: Requirements 1.3**
        """
        # Derive key twice with same inputs
        key1 = derive_key_from_passphrase(passphrase, salt)
        key2 = derive_key_from_passphrase(passphrase, salt)

        # Keys should be identical
        assert key1 == key2

        # Keys should be 32 bytes (256 bits for AES-256)
        assert len(key1) == 32
        assert len(key2) == 32

    @pytest.mark.property
    @settings(deadline=5000)  # Allow 5 seconds for Argon2id computation
    @given(
        passphrase=st.text(min_size=1, max_size=100),
        salt1=st.binary(min_size=SALT_SIZE, max_size=SALT_SIZE),
        salt2=st.binary(min_size=SALT_SIZE, max_size=SALT_SIZE),
    )
    def test_key_derivation_salt_sensitivity(
        self, passphrase: str, salt1: bytes, salt2: bytes
    ) -> None:
        """
        Property 2: Key Derivation Salt Sensitivity

        For any passphrase and two different salts, calling derive_key_from_passphrase
        SHALL produce different keys.

        **Feature: shellock, Property 2: Key Derivation Salt Sensitivity**
        **Validates: Requirements 1.4**
        """
        # Skip test if salts are identical (we need different salts)
        if salt1 == salt2:
            return

        # Derive keys with same passphrase but different salts
        key1 = derive_key_from_passphrase(passphrase, salt1)
        key2 = derive_key_from_passphrase(passphrase, salt2)

        # Keys should be different when salts are different
        assert key1 != key2

        # Both keys should be 32 bytes
        assert len(key1) == 32
        assert len(key2) == 32


class TestEnvelope:
    """Tests for Envelope dataclass and serialization."""

    def test_envelope_constants(self) -> None:
        """Test that all required constants are properly defined."""
        assert MAGIC_HEADER == b"SHELLOCKv1"
        assert len(MAGIC_HEADER) == 10
        assert SALT_SIZE == 16
        assert NONCE_SIZE == 12
        assert TAG_SIZE == 16
        assert ENVELOPE_HEADER_SIZE == 54  # 10 + 16 + 12 + 16

    @given(
        salt=st.binary(min_size=SALT_SIZE, max_size=SALT_SIZE),
        nonce=st.binary(min_size=NONCE_SIZE, max_size=NONCE_SIZE),
        tag=st.binary(min_size=TAG_SIZE, max_size=TAG_SIZE),
        ciphertext=st.binary(min_size=0, max_size=1000),
    )
    def test_envelope_serialization_round_trip(
        self, salt: bytes, nonce: bytes, tag: bytes, ciphertext: bytes
    ) -> None:
        """
        Property 5: Envelope Serialization Round Trip

        For any valid Envelope object, calling to_bytes() then from_bytes()
        SHALL produce an equivalent Envelope object.

        **Feature: shellock, Property 5: Envelope Serialization Round Trip**
        **Validates: Requirements 2.5, 3.2**
        """
        # Create envelope with valid magic header
        original_envelope = Envelope(
            magic=MAGIC_HEADER, salt=salt, nonce=nonce, tag=tag, ciphertext=ciphertext
        )

        # Serialize to bytes
        serialized = original_envelope.to_bytes()

        # Deserialize back to envelope
        parsed_envelope = Envelope.from_bytes(serialized)

        # Should be equivalent
        assert parsed_envelope.magic == original_envelope.magic
        assert parsed_envelope.salt == original_envelope.salt
        assert parsed_envelope.nonce == original_envelope.nonce
        assert parsed_envelope.tag == original_envelope.tag
        assert parsed_envelope.ciphertext == original_envelope.ciphertext

    def test_envelope_invalid_magic_header(self) -> None:
        """Test that InvalidFileFormatError is raised for invalid magic header."""
        # Create data with wrong magic header
        wrong_magic = b"WRONGMAGIC"  # 10 bytes but wrong content
        salt = b"a" * SALT_SIZE
        nonce = b"b" * NONCE_SIZE
        tag = b"c" * TAG_SIZE
        ciphertext = b"test data"

        invalid_data = wrong_magic + salt + nonce + tag + ciphertext

        # Should raise InvalidFileFormatError
        with pytest.raises(InvalidFileFormatError, match="Invalid magic header"):
            Envelope.from_bytes(invalid_data)

    def test_envelope_data_too_short(self) -> None:
        """Test that InvalidFileFormatError is raised for data that's too short."""
        # Data shorter than minimum header size
        short_data = b"short"

        with pytest.raises(InvalidFileFormatError, match="Data too short"):
            Envelope.from_bytes(short_data)

    def test_envelope_minimum_valid_size(self) -> None:
        """Test parsing envelope with minimum valid size (header only, no ciphertext)."""
        # Create minimal valid envelope (header only)
        salt = b"a" * SALT_SIZE
        nonce = b"b" * NONCE_SIZE
        tag = b"c" * TAG_SIZE

        minimal_data = MAGIC_HEADER + salt + nonce + tag

        # Should parse successfully with empty ciphertext
        envelope = Envelope.from_bytes(minimal_data)
        assert envelope.magic == MAGIC_HEADER
        assert envelope.salt == salt
        assert envelope.nonce == nonce
        assert envelope.tag == tag
        assert envelope.ciphertext == b""

    @pytest.mark.property
    @given(
        wrong_magic=st.binary(min_size=10, max_size=10),
        salt=st.binary(min_size=SALT_SIZE, max_size=SALT_SIZE),
        nonce=st.binary(min_size=NONCE_SIZE, max_size=NONCE_SIZE),
        tag=st.binary(min_size=TAG_SIZE, max_size=TAG_SIZE),
        ciphertext=st.binary(min_size=0, max_size=1000),
    )
    def test_invalid_magic_header_detection(
        self,
        wrong_magic: bytes,
        salt: bytes,
        nonce: bytes,
        tag: bytes,
        ciphertext: bytes,
    ) -> None:
        """
        Property 6: Invalid Magic Header Detection

        For any byte sequence that does not start with b"SHELLOCKv1",
        calling decrypt_bytes SHALL raise an InvalidFileFormatError.

        **Feature: shellock, Property 6: Invalid Magic Header Detection**
        **Validates: Requirements 3.3**
        """
        # Skip test if the generated magic header happens to be the correct one
        if wrong_magic == MAGIC_HEADER:
            return

        # Create data with wrong magic header
        invalid_data = wrong_magic + salt + nonce + tag + ciphertext

        # Should raise InvalidFileFormatError when parsing
        with pytest.raises(InvalidFileFormatError, match="Invalid magic header"):
            Envelope.from_bytes(invalid_data)


class TestEncryption:
    """Tests for encryption and decryption functions."""

    @pytest.mark.property
    @settings(deadline=10000)  # Allow 10 seconds for Argon2id computation
    @given(
        plaintext=st.binary(min_size=0, max_size=10000),
        passphrase=st.text(min_size=1, max_size=100),
    )
    def test_encryption_decryption_round_trip(
        self, plaintext: bytes, passphrase: str
    ) -> None:
        """
        Property 3: Encryption-Decryption Round Trip

        For any valid plaintext bytes and passphrase, encrypting with encrypt_bytes
        then decrypting with decrypt_bytes using the same passphrase SHALL return
        bytes equal to the original plaintext.

        **Feature: shellock, Property 3: Encryption-Decryption Round Trip**
        **Validates: Requirements 4.1**
        """
        # Encrypt the plaintext
        encrypted = encrypt_bytes(plaintext, passphrase)

        # Decrypt with the same passphrase
        decrypted = decrypt_bytes(encrypted, passphrase)

        # Decrypted plaintext should match original
        assert decrypted == plaintext

    @pytest.mark.property
    @settings(deadline=10000)  # Allow 10 seconds for Argon2id computation
    @given(
        plaintext=st.binary(min_size=0, max_size=10000),
        passphrase=st.text(min_size=1, max_size=100),
    )
    def test_encryption_non_determinism(
        self, plaintext: bytes, passphrase: str
    ) -> None:
        """
        Property 4: Encryption Non-Determinism

        For any plaintext bytes and passphrase, calling encrypt_bytes twice
        SHALL produce different ciphertexts (due to random salt and nonce).

        **Feature: shellock, Property 4: Encryption Non-Determinism**
        **Validates: Requirements 4.2**
        """
        # Encrypt the plaintext twice with the same passphrase
        encrypted1 = encrypt_bytes(plaintext, passphrase)
        encrypted2 = encrypt_bytes(plaintext, passphrase)

        # The two ciphertexts should be different (due to random salt and nonce)
        # This is a probabilistic property - with overwhelming probability they differ
        assert encrypted1 != encrypted2

        # Both should still decrypt to the same plaintext
        decrypted1 = decrypt_bytes(encrypted1, passphrase)
        decrypted2 = decrypt_bytes(encrypted2, passphrase)

        assert decrypted1 == plaintext
        assert decrypted2 == plaintext

    @pytest.mark.property
    @settings(deadline=10000)  # Allow 10 seconds for Argon2id computation
    @given(
        plaintext=st.binary(min_size=0, max_size=10000),
        passphrase=st.text(min_size=1, max_size=100),
        wrong_passphrase=st.text(min_size=1, max_size=100),
    )
    def test_wrong_passphrase_detection(
        self, plaintext: bytes, passphrase: str, wrong_passphrase: str
    ) -> None:
        """
        Property 7: Wrong Passphrase Detection

        For any encrypted envelope and a passphrase different from the one used
        for encryption, calling decrypt_bytes SHALL raise an AuthenticationError.

        **Feature: shellock, Property 7: Wrong Passphrase Detection**
        **Validates: Requirements 3.4**
        """
        # Skip test if passphrases are identical (we need different passphrases)
        if passphrase == wrong_passphrase:
            return

        # Encrypt with the correct passphrase
        encrypted = encrypt_bytes(plaintext, passphrase)

        # Attempt to decrypt with a different passphrase
        # Should raise AuthenticationError
        with pytest.raises(AuthenticationError, match="Authentication failed"):
            decrypt_bytes(encrypted, wrong_passphrase)


class TestSymmetricKeyEncryption:
    """Tests for symmetric key-based encryption functions."""

    def test_symmetric_key_size_validation_encrypt(self) -> None:
        """Test that encrypt_bytes_key validates key size."""
        plaintext = b"test data"

        # Test with wrong key size (too short)
        short_key = b"short"
        with pytest.raises(ValueError, match="Symmetric key must be"):
            encrypt_bytes_key(plaintext, short_key)

        # Test with wrong key size (too long)
        long_key = b"a" * 64
        with pytest.raises(ValueError, match="Symmetric key must be"):
            encrypt_bytes_key(plaintext, long_key)

    def test_symmetric_key_size_validation_decrypt(self) -> None:
        """Test that decrypt_bytes_key validates key size."""
        # Create a valid encrypted blob
        valid_key = b"a" * KEY_SIZE
        plaintext = b"test data"
        encrypted = encrypt_bytes_key(plaintext, valid_key)

        # Test with wrong key size (too short)
        short_key = b"short"
        with pytest.raises(ValueError, match="Symmetric key must be"):
            decrypt_bytes_key(encrypted, short_key)

        # Test with wrong key size (too long)
        long_key = b"a" * 64
        with pytest.raises(ValueError, match="Symmetric key must be"):
            decrypt_bytes_key(encrypted, long_key)

    @pytest.mark.property
    @given(
        plaintext=st.binary(min_size=0, max_size=10000),
        symmetric_key=st.binary(min_size=KEY_SIZE, max_size=KEY_SIZE),
    )
    def test_symmetric_key_encryption_round_trip(
        self, plaintext: bytes, symmetric_key: bytes
    ) -> None:
        """
        Property 11: Symmetric Key-Based Encryption Round Trip

        For any valid plaintext bytes and 32-byte symmetric key, encrypting with
        encrypt_bytes_key then decrypting with decrypt_bytes_key using the same key
        SHALL return bytes equal to the original plaintext.

        **Feature: shellock, Property 11: Symmetric Key-Based Encryption Round Trip**
        **Validates: Requirements 11.1, 11.2**
        """
        # Encrypt the plaintext with the symmetric key
        encrypted = encrypt_bytes_key(plaintext, symmetric_key)

        # Decrypt with the same key
        decrypted = decrypt_bytes_key(encrypted, symmetric_key)

        # Decrypted plaintext should match original
        assert decrypted == plaintext

    @pytest.mark.property
    @given(
        plaintext=st.binary(min_size=0, max_size=10000),
        symmetric_key=st.binary(min_size=KEY_SIZE, max_size=KEY_SIZE),
        wrong_key=st.binary(min_size=KEY_SIZE, max_size=KEY_SIZE),
    )
    def test_symmetric_key_wrong_key_detection(
        self, plaintext: bytes, symmetric_key: bytes, wrong_key: bytes
    ) -> None:
        """
        Test that decryption with wrong symmetric key raises AuthenticationError.

        For any encrypted envelope and a different symmetric key, calling
        decrypt_bytes_key SHALL raise an AuthenticationError.
        """
        # Skip test if keys are identical (we need different keys)
        if symmetric_key == wrong_key:
            return

        # Encrypt with the correct key
        encrypted = encrypt_bytes_key(plaintext, symmetric_key)

        # Attempt to decrypt with a different key
        # Should raise AuthenticationError
        with pytest.raises(AuthenticationError, match="Authentication failed"):
            decrypt_bytes_key(encrypted, wrong_key)

    def test_symmetric_key_envelope_format(self) -> None:
        """Test that symmetric key encryption uses correct envelope format."""
        key = b"a" * KEY_SIZE
        plaintext = b"test data"

        # Encrypt
        encrypted = encrypt_bytes_key(plaintext, key)

        # Parse envelope to verify format
        envelope = Envelope.from_bytes(encrypted)

        # Verify envelope structure
        assert envelope.magic == MAGIC_HEADER
        assert len(envelope.salt) == SALT_SIZE
        assert len(envelope.nonce) == NONCE_SIZE
        assert len(envelope.tag) == TAG_SIZE
        assert len(envelope.ciphertext) > 0

        # For symmetric key encryption, salt should be all zeros (not used)
        assert envelope.salt == b"\x00" * SALT_SIZE

    def test_symmetric_key_non_determinism(self) -> None:
        """Test that symmetric key encryption produces different ciphertexts each time."""
        key = b"a" * KEY_SIZE
        plaintext = b"test data"

        # Encrypt twice with the same key
        encrypted1 = encrypt_bytes_key(plaintext, key)
        encrypted2 = encrypt_bytes_key(plaintext, key)

        # The two ciphertexts should be different (due to random nonce)
        assert encrypted1 != encrypted2

        # Both should decrypt to the same plaintext
        decrypted1 = decrypt_bytes_key(encrypted1, key)
        decrypted2 = decrypt_bytes_key(encrypted2, key)

        assert decrypted1 == plaintext
        assert decrypted2 == plaintext


class TestAsymmetricEncryption:
    """Tests for asymmetric encryption functions."""

    def test_generate_keypair(self) -> None:
        """Test that generate_keypair produces valid PEM-formatted keys."""
        private_key_pem, public_key_pem = generate_keypair()

        # Both should be bytes
        assert isinstance(private_key_pem, bytes)
        assert isinstance(public_key_pem, bytes)

        # Both should contain PEM markers
        assert b"-----BEGIN" in private_key_pem
        assert b"-----END" in private_key_pem
        assert b"-----BEGIN" in public_key_pem
        assert b"-----END" in public_key_pem

        # Private key should be longer than public key (contains more data)
        assert len(private_key_pem) > len(public_key_pem)

    def test_generate_keypair_uniqueness(self) -> None:
        """Test that generate_keypair produces different keys each time."""
        keypair1 = generate_keypair()
        keypair2 = generate_keypair()

        # Keys should be different
        assert keypair1[0] != keypair2[0]  # Different private keys
        assert keypair1[1] != keypair2[1]  # Different public keys

    @pytest.mark.property
    @given(plaintext=st.binary(min_size=0, max_size=10000))
    def test_asymmetric_encryption_round_trip(self, plaintext: bytes) -> None:
        """
        Property 9: Asymmetric Encryption Round Trip

        For any valid plaintext bytes and Ed25519 keypair, encrypting with the
        public key then decrypting with the private key SHALL return bytes equal
        to the original plaintext.

        **Feature: shellock, Property 9: Asymmetric Encryption Round Trip**
        **Validates: Requirements 9.1, 9.4**
        """
        # Generate a keypair
        private_key_pem, public_key_pem = generate_keypair()

        # Encrypt with public key
        encrypted = encrypt_bytes_public(plaintext, public_key_pem)

        # Decrypt with private key
        decrypted = decrypt_bytes_private(encrypted, private_key_pem)

        # Decrypted plaintext should match original
        assert decrypted == plaintext

    def test_asymmetric_encryption_with_wrong_private_key(self) -> None:
        """Test that decryption with wrong private key raises AuthenticationError."""
        plaintext = b"test data"

        # Generate two different keypairs
        private_key1_pem, public_key1_pem = generate_keypair()
        private_key2_pem, public_key2_pem = generate_keypair()

        # Encrypt with first public key
        encrypted = encrypt_bytes_public(plaintext, public_key1_pem)

        # Attempt to decrypt with second private key
        # Should raise AuthenticationError
        with pytest.raises(AuthenticationError, match="Authentication failed"):
            decrypt_bytes_private(encrypted, private_key2_pem)

    def test_asymmetric_encryption_non_determinism(self) -> None:
        """Test that asymmetric encryption produces different ciphertexts each time."""
        plaintext = b"test data"
        private_key_pem, public_key_pem = generate_keypair()

        # Encrypt twice with the same public key
        encrypted1 = encrypt_bytes_public(plaintext, public_key_pem)
        encrypted2 = encrypt_bytes_public(plaintext, public_key_pem)

        # The two ciphertexts should be different (due to ephemeral keypair)
        assert encrypted1 != encrypted2

        # Both should decrypt to the same plaintext
        decrypted1 = decrypt_bytes_private(encrypted1, private_key_pem)
        decrypted2 = decrypt_bytes_private(encrypted2, private_key_pem)

        assert decrypted1 == plaintext
        assert decrypted2 == plaintext

    def test_asymmetric_encryption_invalid_public_key(self) -> None:
        """Test that invalid public key format raises InvalidFileFormatError."""
        plaintext = b"test data"
        invalid_key = b"not a valid PEM key"

        with pytest.raises(InvalidFileFormatError, match="Invalid public key format"):
            encrypt_bytes_public(plaintext, invalid_key)

    def test_asymmetric_decryption_invalid_private_key(self) -> None:
        """Test that invalid private key format raises InvalidFileFormatError."""
        # Create a valid encrypted blob first
        private_key_pem, public_key_pem = generate_keypair()
        plaintext = b"test data"
        encrypted = encrypt_bytes_public(plaintext, public_key_pem)

        # Try to decrypt with invalid private key
        invalid_key = b"not a valid PEM key"

        with pytest.raises(InvalidFileFormatError, match="Invalid private key format"):
            decrypt_bytes_private(encrypted, invalid_key)

    def test_asymmetric_encryption_empty_plaintext(self) -> None:
        """Test that asymmetric encryption works with empty plaintext."""
        plaintext = b""
        private_key_pem, public_key_pem = generate_keypair()

        # Encrypt empty plaintext
        encrypted = encrypt_bytes_public(plaintext, public_key_pem)

        # Decrypt
        decrypted = decrypt_bytes_private(encrypted, private_key_pem)

        # Should get back empty plaintext
        assert decrypted == b""

    def test_asymmetric_encryption_large_plaintext(self) -> None:
        """Test that asymmetric encryption works with large plaintext."""
        plaintext = b"x" * 100000  # 100 KB
        private_key_pem, public_key_pem = generate_keypair()

        # Encrypt large plaintext
        encrypted = encrypt_bytes_public(plaintext, public_key_pem)

        # Decrypt
        decrypted = decrypt_bytes_private(encrypted, private_key_pem)

        # Should get back original plaintext
        assert decrypted == plaintext
