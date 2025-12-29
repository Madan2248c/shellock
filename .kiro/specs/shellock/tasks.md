# Implementation Plan: Shellock

## Overview

This plan implements Shellock in Python, following a bottom-up approach: crypto primitives first, then the file API, and finally the CLI. Property-based tests are included alongside implementation tasks to catch errors early.

## Tasks

- [x] 1. Set up project structure and dependencies
  - Create directory structure: `shellock/`, `tests/`, `docs/`
  - Create `pyproject.toml` with modern build system (Hatchling) and dependencies
  - Dependencies: `cryptography>=41.0.0`, `click>=8.0.0`, `rich>=13.0.0`, `zeroize-python>=0.1.0`
  - Dev dependencies: `pytest>=7.0`, `pytest-cov>=4.0`, `hypothesis>=6.0`, `ruff>=0.1.0`, `mypy>=1.0`
  - Create `shellock/__init__.py` with version and public exports
  - Create custom exception classes in `shellock/exceptions.py`
  - Set up pre-commit hooks with ruff, mypy, and pytest
  - _Requirements: 3.3, 3.4, 3.5_

- [ ] 2. Implement crypto module
  - [x] 2.1 Implement `derive_key_from_passphrase` function with secure memory handling
    - Use Argon2id from `cryptography.hazmat.primitives.kdf.argon2`
    - Configure with memory_cost=65536, time_cost=2, parallelism=4 (OWASP recommendations)
    - Return 32-byte derived key
    - Implement secure memory cleanup using `zeroize-python`
    - Use `secrets.compare_digest()` for any key comparisons
    - _Requirements: 1.1, 1.2, 1.3, 1.4_

  - [x] 2.2 Write property test for key derivation determinism
    - **Property 1: Key Derivation Determinism**
    - **Validates: Requirements 1.3**

  - [x] 2.3 Write property test for key derivation salt sensitivity
    - **Property 2: Key Derivation Salt Sensitivity**
    - **Validates: Requirements 1.4**

  - [x] 2.4 Implement `Envelope` dataclass with `to_bytes` and `from_bytes`
    - Define constants: MAGIC_HEADER, SALT_SIZE, NONCE_SIZE, TAG_SIZE
    - Implement serialization and parsing
    - Raise `InvalidFileFormatError` for invalid magic header
    - _Requirements: 2.5, 2.6, 3.2, 3.3_

  - [x] 2.5 Write property test for envelope serialization round trip
    - **Property 5: Envelope Serialization Round Trip**
    - **Validates: Requirements 2.5, 3.2**

  - [x] 2.6 Implement `encrypt_bytes` function with secure random generation
    - Generate random salt (16 bytes) and nonce (12 bytes) using `secrets.token_bytes()`
    - Derive key using `derive_key_from_passphrase`
    - Encrypt with AES-256-GCM using `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
    - Return serialized envelope
    - Implement secure cleanup of intermediate values
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

  - [x] 2.7 Implement `decrypt_bytes` function with secure error handling
    - Parse envelope using `Envelope.from_bytes`
    - Derive key using `derive_key_from_passphrase`
    - Decrypt with AES-256-GCM
    - Raise `AuthenticationError` on decryption failure (constant-time error handling)
    - Implement secure cleanup of derived keys and intermediate values
    - Use generic error messages to prevent information leakage
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

  - [x] 2.8 Write property test for encryption-decryption round trip
    - **Property 3: Encryption-Decryption Round Trip**
    - **Validates: Requirements 4.1**

  - [x] 2.9 Write property test for encryption non-determinism
    - **Property 4: Encryption Non-Determinism**
    - **Validates: Requirements 4.2**

  - [x] 2.10 Write property test for invalid magic header detection
    - **Property 6: Invalid Magic Header Detection**
    - **Validates: Requirements 3.3**

  - [x] 2.11 Write property test for wrong passphrase detection
    - **Property 7: Wrong Passphrase Detection**
    - **Validates: Requirements 3.4**

  - [x] 2.13 Implement asymmetric encryption functions
    - Implement `generate_keypair()` using Ed25519
    - Implement `encrypt_bytes_public()` with hybrid encryption (Ed25519 + AES-256-GCM)
    - Implement `decrypt_bytes_private()` with hybrid decryption
    - Use secure random generation for symmetric keys
    - Implement proper key format handling (PEM)
    - _Requirements: 8.2, 8.4, 9.1, 9.2, 9.3, 9.4_

  - [x] 2.14 Write property test for asymmetric encryption round trip
    - **Property 9: Asymmetric Encryption Round Trip**
    - **Validates: Requirements 9.1, 9.4**

  - [x] 2.16 Implement symmetric key-based encryption functions
    - Implement `encrypt_bytes_key()` using direct symmetric key (no KDF)
    - Implement `decrypt_bytes_key()` using direct symmetric key
    - Use same envelope format as passphrase-based encryption but skip KDF step
    - Implement secure key file reading and validation (base64 decoding)
    - _Requirements: 11.1, 11.2, 11.3, 11.4_

  - [x] 2.17 Write property test for symmetric key-based encryption round trip
    - **Property 11: Symmetric Key-Based Encryption Round Trip**
    - **Validates: Requirements 11.1, 11.2**

- [x] 3. Checkpoint - Crypto module complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Implement file-based API
  - [x] 4.1 Implement `encrypt_file` function with secure file handling
    - Read input file as bytes using secure temporary file handling
    - Call `encrypt_bytes`
    - Write envelope to output file with appropriate permissions (600)
    - Raise `FileNotFoundError` for missing input file
    - Use `tempfile.NamedTemporaryFile()` for any intermediate files
    - _Requirements: 5.1, 5.3_

  - [x] 4.2 Implement `decrypt_file` function with secure file handling
    - Read encrypted file as bytes using secure file operations
    - Call `decrypt_bytes`
    - Write plaintext to output file with restrictive permissions (600)
    - Raise `FileNotFoundError` for missing input file
    - Ensure no sensitive data persists in temporary files
    - _Requirements: 5.2, 5.3, 5.4_

  - [x] 4.3 Implement asymmetric file API functions
    - Implement `encrypt_file_public()` function
    - Implement `decrypt_file_private()` function
    - Handle PEM key file loading and validation
    - Implement secure file handling with proper error messages
    - _Requirements: 9.1, 9.4_

  - [x] 4.5 Implement symmetric key-based file API functions
    - Implement `encrypt_file_key()` function
    - Implement `decrypt_file_key()` function
    - Handle base64 key file loading and validation
    - Implement secure file handling with proper error messages
    - _Requirements: 11.1, 11.2, 11.3, 11.4_

  - [x] 4.6 Write comprehensive file API tests
    - Test encrypt_file and decrypt_file round trip with temp files
    - Test encrypt_file_public and decrypt_file_private round trip
    - Test encrypt_file_key and decrypt_file_key round trip
    - Test FileNotFoundError for missing input files and key files
    - Test key format validation and error handling for all key types
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 9.1, 9.4, 11.1, 11.2_

- [ ] 5. Checkpoint - API module complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Implement CLI with Click framework and Rich UI
  - [x] 6.1 Implement CLI argument parser with Click subcommands
    - Create main CLI group with `encrypt`, `decrypt`, `generate-key` subcommands
    - Add comprehensive `--help` for all commands with examples
    - Use Click's built-in validation and type checking
    - _Requirements: 9.1, 9.2, 9.3, 9.4_

  - [x] 6.2 Implement `encrypt` subcommand with Rich progress display
    - Parse INPUT, --out, --passphrase arguments using Click
    - Prompt for passphrase with `getpass` if not provided
    - Display progress with Rich spinners during encryption
    - Call `encrypt_file` from API
    - Handle errors with user-friendly messages and appropriate exit codes
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

  - [x] 6.3 Implement `decrypt` subcommand with Rich progress display
    - Parse INPUT, --out, --passphrase arguments using Click
    - Prompt for passphrase with `getpass` if not provided
    - Display progress with Rich spinners during decryption
    - Call `decrypt_file` from API
    - Handle errors with generic messages and appropriate exit codes
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [x] 6.4 Implement `generate-key` subcommand with type selection
    - Parse --type and --out arguments using Click
    - Support both 'symmetric' and 'asymmetric' key types
    - Add confirmation prompt using Click's confirmation_option
    - Generate appropriate key type using secure random generation
    - For symmetric: write base64-encoded key to file
    - For asymmetric: write private key to file with 600 permissions, display public key
    - Display success message with Rich formatting
    - _Requirements: 8.1, 8.2, 8.3, 8.4_

  - [x] 6.5 Implement asymmetric encryption subcommands
    - Implement `encrypt-public` subcommand with public key file input
    - Implement `decrypt-private` subcommand with private key file input
    - Handle optional passphrase prompts for encrypted private keys
    - Display progress with Rich spinners during operations
    - Handle errors with user-friendly messages and appropriate exit codes
    - _Requirements: 9.1, 9.4_

  - [x] 6.6 Implement symmetric key-based encryption subcommands
    - Implement `encrypt-key` subcommand with symmetric key file input
    - Implement `decrypt-key` subcommand with symmetric key file input
    - Handle key file validation and base64 decoding
    - Display progress with Rich spinners during operations
    - Handle errors with user-friendly messages and appropriate exit codes
    - _Requirements: 11.1, 11.2, 11.5_

  - [x] 6.7 Write comprehensive CLI tests
    - Test encrypt/decrypt round trip via subprocess with Rich output capture
    - Test encrypt-public/decrypt-private round trip via subprocess
    - Test encrypt-key/decrypt-key round trip via subprocess
    - Test error exit codes and user-friendly error messages
    - Test generate-key for both symmetric and asymmetric types
    - Test key file format validation and permissions for all key types
    - Test interactive passphrase prompts and confirmation dialogs
    - Test CLI help output and argument validation for all commands
    - _Requirements: 6.1, 6.3, 6.4, 7.1, 7.3, 7.4, 7.5, 8.1, 8.2, 8.3, 8.4, 9.1, 9.4, 11.1, 11.2, 12.1-12.8_

- [ ] 7. Final checkpoint - All tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Create production-grade documentation and packaging
  - [x] 8.1 Create comprehensive README.md
    - Add project description with security guarantees
    - Add installation instructions via pip
    - Add CLI usage examples with Rich output screenshots
    - Add Python API examples with security best practices
    - Add security notes about threat model and limitations
    - Add contributing guidelines and development setup
    - _Requirements: All_

  - [x] 8.2 Create LICENSE file and security documentation
    - Add MIT license text
    - Create SECURITY.md with vulnerability reporting process
    - Create CHANGELOG.md for version history
    - _Requirements: N/A_

  - [x] 8.3 Set up CI/CD pipeline with GitHub Actions
    - Configure automated testing across Python 3.8-3.12
    - Set up code quality checks with ruff and mypy
    - Configure security testing and vulnerability scanning
    - Set up trusted publishing to PyPI
    - Configure automated dependency updates with Dependabot
    - _Requirements: N/A_

## Notes

- All tasks are required for production-grade security and quality
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation and security review
- Property tests validate universal correctness properties with security focus
- Unit tests validate specific examples, edge cases, and security scenarios
- The `hypothesis` library is used for property-based testing with security-focused generators
- Modern tooling: Click for CLI, Rich for UI, Ruff for linting, MyPy for type checking
- Security-first approach: secure memory handling, constant-time operations, information leakage prevention
- Production-ready: comprehensive testing, CI/CD, documentation, and distribution security
