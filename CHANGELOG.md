# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet

### Changed
- Nothing yet

### Fixed
- Nothing yet

## [0.1.0] - 2025-12-29

### Added

#### Core Features
- AES-256-GCM encryption with authenticated encryption
- Argon2id key derivation with OWASP-recommended parameters
- Versioned binary envelope format (`SHELLOCKv1`)

#### Encryption Modes
- Passphrase-based encryption (`encrypt`/`decrypt` commands)
- Symmetric key-based encryption (`encrypt-key`/`decrypt-key` commands)
- Asymmetric encryption with X25519 (`encrypt-public`/`decrypt-private` commands)

#### CLI
- Rich terminal UI with progress indicators
- Secure passphrase prompts (no echo)
- Comprehensive help for all commands
- Key generation (`generate-key` command)

#### Python API
- `encrypt_file()` / `decrypt_file()` - Passphrase-based file encryption
- `encrypt_file_key()` / `decrypt_file_key()` - Symmetric key file encryption
- `encrypt_file_public()` / `decrypt_file_private()` - Asymmetric file encryption
- `encrypt_bytes()` / `decrypt_bytes()` - Byte-level operations
- `generate_keypair()` - X25519 keypair generation

#### Security
- Constant-time comparison for authentication
- Secure file permissions (600) on output files
- Generic error messages to prevent information leakage
- Random salt and nonce for each encryption

#### Testing
- Property-based tests with Hypothesis
- Unit tests for all modules
- Security-focused test cases

#### Documentation
- Comprehensive README with examples
- Security policy (SECURITY.md)
- API documentation

### Security Notes

This is the initial release. The cryptographic implementation uses:
- `cryptography` library (well-audited)
- NIST-approved algorithms (AES-256-GCM)
- OWASP-recommended key derivation (Argon2id)

[Unreleased]: https://github.com/Madan2248c/shellock/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Madan2248c/shellock/releases/tag/v0.1.0
