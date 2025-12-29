# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

We take the security of Shellock seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### How to Report

Please report security vulnerabilities by emailing:

**madangopalboddu123@gmail.com**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

### What to Include

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, cryptographic weakness, information disclosure)
- Full paths of source file(s) related to the issue
- Location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### What to Expect

After you submit a report, we will:

1. **Acknowledge receipt** within 48 hours
2. **Confirm the vulnerability** and determine its impact
3. **Develop a fix** and prepare a security release
4. **Notify you** when the fix is ready
5. **Publicly disclose** the vulnerability after the fix is released

### Disclosure Policy

- We follow a 90-day disclosure timeline
- We will coordinate with you on the disclosure date
- We will credit you in the security advisory (unless you prefer to remain anonymous)

## Security Best Practices

When using Shellock, please follow these security best practices:

### Passphrase Security

- Use strong, unique passphrases (16+ characters recommended)
- Never commit passphrases to version control
- Use environment variables or secure vaults in production
- Consider using a password manager

### Key Management

- Store private keys securely with restricted permissions (chmod 600)
- Never share private keys
- Rotate keys periodically
- Use separate keys for different environments

### File Handling

- Shellock sets secure permissions (600) on output files automatically
- Verify file permissions on sensitive files
- Use secure deletion for plaintext files after encryption

### Environment Security

- Keep your system and dependencies updated
- Use virtual environments to isolate dependencies
- Monitor for security advisories in dependencies

## Known Security Considerations

### Cryptographic Choices

Shellock uses:

- **AES-256-GCM** for authenticated encryption (NIST SP 800-38D)
- **Argon2id** for key derivation (RFC 9106, OWASP recommended)
- **X25519** for asymmetric key exchange (RFC 7748)

These are current best practices as of 2025.

### Memory Security

Shellock attempts to clear sensitive data from memory after use. However:

- Python's garbage collector may not immediately free memory
- Memory may be swapped to disk by the operating system
- For high-security applications, consider additional OS-level protections

### Side-Channel Attacks

Shellock uses constant-time comparison for authentication. However:

- Hardware-level side channels are outside our control
- For high-security applications, consider dedicated hardware

## Security Updates

Security updates are released as patch versions (e.g., 0.1.1, 0.1.2).

To stay updated:

```bash
# Check for updates
pip list --outdated

# Update Shellock
pip install --upgrade shellock
```

## Contact

For security-related questions that are not vulnerabilities, you can:

- Open a GitHub Discussion
- Email madangopalboddu123@gmail.com

Thank you for helping keep Shellock and its users safe!
