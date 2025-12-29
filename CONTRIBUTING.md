# Contributing to Shellock

Thank you for your interest in contributing to Shellock! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check existing issues to avoid duplicates.

When creating a bug report, include:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- Your environment (OS, Python version, Shellock version)
- Any relevant logs or error messages

### Suggesting Features

Feature suggestions are welcome! Please:

- Check existing issues and discussions first
- Provide a clear use case
- Explain why this feature would be useful
- Consider security implications

### Security Vulnerabilities

**Do not report security vulnerabilities through public issues.**

Please see [SECURITY.md](SECURITY.md) for our security policy and how to report vulnerabilities responsibly.

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- A virtual environment tool (venv, virtualenv, etc.)

### Setting Up Your Development Environment

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/shellock.git
cd shellock

# Create a virtual environment
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

# Run specific test file
pytest tests/test_crypto.py

# Run property-based tests with more examples
pytest -m property --hypothesis-profile=ci
```

### Code Quality

We use several tools to maintain code quality:

```bash
# Format code with Ruff
ruff format .

# Lint code with Ruff
ruff check .

# Type check with MyPy
mypy shellock/

# Run all pre-commit checks
pre-commit run --all-files
```

## Pull Request Process

### Before Submitting

1. **Create an issue first** for significant changes
2. **Fork the repository** and create a feature branch
3. **Write tests** for new functionality
4. **Update documentation** as needed
5. **Run all checks** locally before pushing

### Branch Naming

Use descriptive branch names:

- `feature/add-key-rotation`
- `fix/memory-leak-in-decrypt`
- `docs/update-api-examples`
- `security/constant-time-comparison`

### Commit Messages

Follow conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `security`: Security improvements
- `chore`: Maintenance tasks

Examples:
```
feat(crypto): add key rotation support
fix(cli): handle empty passphrase correctly
docs(readme): add asymmetric encryption examples
security(crypto): use constant-time comparison
```

### Pull Request Template

When creating a PR, include:

- **Description**: What does this PR do?
- **Related Issue**: Link to the related issue
- **Type of Change**: Bug fix, feature, docs, etc.
- **Testing**: How was this tested?
- **Security Considerations**: Any security implications?
- **Checklist**:
  - [ ] Tests pass locally
  - [ ] Code follows style guidelines
  - [ ] Documentation updated
  - [ ] No security vulnerabilities introduced

### Review Process

1. All PRs require at least one review
2. Security-related changes require additional review
3. CI must pass before merging
4. Squash commits when merging

## Coding Standards

### Python Style

- Follow PEP 8 (enforced by Ruff)
- Use type hints for all public functions
- Maximum line length: 88 characters
- Use descriptive variable names

### Documentation

- All public functions must have docstrings
- Use Google-style docstrings
- Include examples in docstrings where helpful

```python
def encrypt_bytes(plaintext: bytes, passphrase: str) -> bytes:
    """
    Encrypt plaintext bytes with a passphrase.

    Uses AES-256-GCM with Argon2id key derivation.

    Args:
        plaintext: The data to encrypt.
        passphrase: The passphrase for key derivation.

    Returns:
        The encrypted envelope as bytes.

    Raises:
        ValueError: If plaintext is empty.

    Example:
        >>> encrypted = encrypt_bytes(b"secret", "passphrase")
        >>> decrypted = decrypt_bytes(encrypted, "passphrase")
        >>> decrypted == b"secret"
        True
    """
```

### Security Guidelines

When contributing security-sensitive code:

1. **Never log sensitive data** (keys, passphrases, plaintext)
2. **Use constant-time comparisons** for authentication
3. **Clear sensitive data** from memory when done
4. **Use secure random** for cryptographic operations
5. **Validate all inputs** before processing
6. **Use generic error messages** to prevent information leakage

### Testing Guidelines

- Write tests for all new functionality
- Include both unit tests and property-based tests
- Test error conditions and edge cases
- Don't mock cryptographic operations in tests

## Project Structure

```
shellock/
├── shellock/           # Main package
│   ├── __init__.py     # Package exports
│   ├── api.py          # File-based API
│   ├── cli.py          # CLI implementation
│   ├── crypto.py       # Core crypto operations
│   └── exceptions.py   # Custom exceptions
├── tests/              # Test suite
│   ├── test_api.py
│   ├── test_cli.py
│   └── test_crypto.py
├── docs/               # Documentation
├── .github/            # GitHub configuration
│   └── workflows/      # CI/CD workflows
├── pyproject.toml      # Project configuration
├── README.md
├── SECURITY.md
├── CHANGELOG.md
└── CONTRIBUTING.md     # This file
```

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue
- **Security**: Email madangopalboddu123@gmail.com

## Recognition

Contributors will be recognized in:

- The CHANGELOG for their contributions
- The README acknowledgments section
- GitHub's contributor list

Thank you for contributing to Shellock! 🔐
