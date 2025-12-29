# Shellock 🔐

[![PyPI version](https://badge.fury.io/py/shellock.svg)](https://badge.fury.io/py/shellock)
[![Python versions](https://img.shields.io/pypi/pyversions/shellock.svg)](https://pypi.org/project/shellock/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/Madan2248c/shellock/actions/workflows/ci.yml/badge.svg)](https://github.com/Madan2248c/shellock/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Madan2248c/shellock/branch/main/graph/badge.svg)](https://codecov.io/gh/Madan2248c/shellock)

Secure encryption for configuration files using AES-256-GCM + Argon2id.

## Overview

Shellock is a Python tool for encrypting and decrypting configuration files (like `.env` files) using modern cryptographic primitives. It provides both a command-line interface and a Python API with security-first design principles.

## Security Guarantees

Shellock is designed with security as the primary concern:

- **Strong Encryption**: AES-256-GCM provides authenticated encryption with 256-bit security
- **Memory-Hard Key Derivation**: Argon2id (OWASP recommended parameters) protects against brute-force attacks
- **Authenticated Encryption**: GCM mode ensures both confidentiality and integrity
- **Random Salt & Nonce**: Each encryption uses cryptographically secure random values
- **Constant-Time Operations**: Prevents timing side-channel attacks
- **Secure Memory Handling**: Sensitive data is cleared from memory after use
- **No Information Leakage**: Generic error messages prevent oracle attacks

### Cryptographic Parameters

| Parameter | Value | Standard |
|-----------|-------|----------|
| Encryption | AES-256-GCM | NIST SP 800-38D |
| Key Derivation | Argon2id | RFC 9106 |
| Memory Cost | 64 MB | OWASP recommendation |
| Time Cost | 2 iterations | OWASP recommendation |
| Parallelism | 4 threads | OWASP recommendation |
| Salt Size | 16 bytes | Best practice |
| Nonce Size | 12 bytes | GCM standard |
| Key Size | 32 bytes | AES-256 |

## Features

- **Multiple Encryption Modes**:
  - Passphrase-based encryption (Argon2id + AES-256-GCM)
  - Symmetric key-based encryption (direct AES-256-GCM)
  - Asymmetric encryption (X25519 + AES-256-GCM hybrid)
- **Rich CLI**: Beautiful command-line interface with progress indicators
- **Python API**: Clean, type-annotated API for programmatic access
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **Modern Python**: Supports Python 3.8+

## Installation

### From PyPI (Recommended)

```bash
pip install shellock
```

### From Source

```bash
git clone https://github.com/Madan2248c/shellock.git
cd shellock
pip install -e .
```

### With Development Dependencies

```bash
pip install -e ".[dev]"
```

## Quick Start

### CLI Usage

#### Passphrase-Based Encryption

```bash
# Encrypt a file (will prompt for passphrase)
shellock encrypt config.env --out config.env.enc

# Encrypt with passphrase on command line (less secure)
shellock encrypt config.env --out config.env.enc --passphrase "my-secret"

# Decrypt a file
shellock decrypt config.env.enc --out config.env
```

#### Symmetric Key Encryption

```bash
# Generate a symmetric key
shellock generate-key --type symmetric --out secret.key

# Encrypt with the key file
shellock encrypt-key config.env --key secret.key --out config.env.enc

# Decrypt with the key file
shellock decrypt-key config.env.enc --key secret.key --out config.env
```

#### Asymmetric (Public Key) Encryption

```bash
# Generate a keypair
shellock generate-key --type asymmetric --out private.pem
# (Public key is displayed - save it to a file)

# Encrypt with public key (anyone can encrypt)
shellock encrypt-public config.env --key public.pem --out config.env.enc

# Decrypt with private key (only key holder can decrypt)
shellock decrypt-private config.env.enc --key private.pem --out config.env
```

### CLI Help

```bash
# General help
shellock --help

# Command-specific help
shellock encrypt --help
shellock decrypt --help
shellock generate-key --help
```


### Python API

#### Basic Encryption/Decryption

```python
from shellock import encrypt_file, decrypt_file

# Encrypt a file with a passphrase
encrypt_file("config.env", "config.env.enc", "my-secure-passphrase")

# Decrypt a file
decrypt_file("config.env.enc", "config.env", "my-secure-passphrase")
```

#### Byte-Level Operations

```python
from shellock import encrypt_bytes, decrypt_bytes

# Encrypt bytes
plaintext = b"SECRET_KEY=abc123\nDB_PASSWORD=hunter2"
encrypted = encrypt_bytes(plaintext, "my-passphrase")

# Decrypt bytes
decrypted = decrypt_bytes(encrypted, "my-passphrase")
assert decrypted == plaintext
```

#### Symmetric Key Operations

```python
import secrets
import base64
from shellock import encrypt_bytes_key, decrypt_bytes_key, KEY_SIZE

# Generate a random key
key = secrets.token_bytes(KEY_SIZE)  # 32 bytes

# Encrypt with the key
plaintext = b"sensitive data"
encrypted = encrypt_bytes_key(plaintext, key)

# Decrypt with the key
decrypted = decrypt_bytes_key(encrypted, key)
assert decrypted == plaintext

# Save key to file (base64 encoded)
with open("secret.key", "w") as f:
    f.write(base64.b64encode(key).decode())
```

#### Asymmetric Encryption

```python
from shellock import (
    generate_keypair,
    encrypt_bytes_public,
    decrypt_bytes_private,
)

# Generate a keypair
private_key_pem, public_key_pem = generate_keypair()

# Save keys
with open("private.pem", "wb") as f:
    f.write(private_key_pem)
with open("public.pem", "wb") as f:
    f.write(public_key_pem)

# Encrypt with public key
plaintext = b"secret message"
encrypted = encrypt_bytes_public(plaintext, public_key_pem)

# Decrypt with private key
decrypted = decrypt_bytes_private(encrypted, private_key_pem)
assert decrypted == plaintext
```

#### Error Handling

```python
from shellock import (
    encrypt_file,
    decrypt_file,
    InvalidFileFormatError,
    AuthenticationError,
)

try:
    decrypt_file("encrypted.env", "decrypted.env", "wrong-passphrase")
except InvalidFileFormatError:
    print("The file is not a valid Shellock encrypted file")
except AuthenticationError:
    print("Wrong passphrase or file has been tampered with")
except FileNotFoundError as e:
    print(f"File not found: {e}")
```

## Security Best Practices

### Passphrase Guidelines

- Use a strong, unique passphrase (16+ characters recommended)
- Consider using a passphrase manager
- Never commit passphrases to version control
- Use environment variables or secure vaults in production

### Key Management

```python
# DO: Generate keys with secure random
import secrets
key = secrets.token_bytes(32)

# DON'T: Use predictable values
key = b"my-weak-key-1234567890123456"  # BAD!
```

### File Permissions

Shellock automatically sets secure permissions (600) on output files. For key files:

```bash
# Ensure key files are protected
chmod 600 private.pem secret.key
```

### Environment Variables

For CI/CD and production environments:

```bash
# Store passphrase in environment variable
export SHELLOCK_PASSPHRASE="your-secure-passphrase"

# Use in scripts
shellock decrypt config.env.enc --out config.env --passphrase "$SHELLOCK_PASSPHRASE"
```

## Threat Model & Limitations

### What Shellock Protects Against

- ✅ Unauthorized access to encrypted files at rest
- ✅ Brute-force attacks on passphrases (via Argon2id)
- ✅ Tampering detection (via GCM authentication)
- ✅ Rainbow table attacks (via random salts)
- ✅ Replay attacks (via random nonces)

### What Shellock Does NOT Protect Against

- ❌ Compromised systems where attacker has memory access
- ❌ Keyloggers capturing passphrases
- ❌ Weak passphrases (use strong passphrases!)
- ❌ Side-channel attacks on the underlying hardware
- ❌ Quantum computing attacks (future consideration)

### Security Assumptions

1. The `cryptography` library is correctly implemented
2. The operating system's random number generator is secure
3. The system running Shellock is not compromised
4. Passphrases are kept secret and are sufficiently strong

## Development

### Setup

```bash
# Clone the repository
git clone https://github.com/Madan2248c/shellock.git
cd shellock

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=shellock --cov-report=html

# Run property-based tests with more examples
pytest -m property --hypothesis-profile=ci

# Run security-focused tests
pytest -m security
```

### Code Quality

```bash
# Format code
ruff format .

# Lint code
ruff check .

# Type check
mypy shellock/

# Run all checks (via pre-commit)
pre-commit run --all-files
```

### Project Structure

```
shellock/
├── shellock/
│   ├── __init__.py      # Package exports
│   ├── api.py           # File-based API
│   ├── cli.py           # Click CLI
│   ├── crypto.py        # Core cryptographic operations
│   └── exceptions.py    # Custom exceptions
├── tests/
│   ├── test_api.py      # API tests
│   ├── test_cli.py      # CLI tests
│   └── test_crypto.py   # Crypto tests (unit + property)
├── docs/
│   └── README.md        # Additional documentation
├── pyproject.toml       # Project configuration
├── README.md            # This file
├── LICENSE              # MIT License
├── SECURITY.md          # Security policy
└── CHANGELOG.md         # Version history
```

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via our [Security Policy](SECURITY.md). See the security policy for details on our responsible disclosure process.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [cryptography](https://cryptography.io/) - The excellent Python cryptographic library
- [Click](https://click.palletsprojects.com/) - CLI framework
- [Rich](https://rich.readthedocs.io/) - Beautiful terminal formatting
- [Hypothesis](https://hypothesis.readthedocs.io/) - Property-based testing

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes.
