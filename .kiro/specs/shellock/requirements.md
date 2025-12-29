# Requirements Document

## Introduction

Shellock is a Python-native tool for encrypting and decrypting configuration files (e.g., `.env`) using strong symmetric cryptography. It provides both a CLI and a Python API, using modern cryptography defaults (Argon2id for key derivation and AES-256-GCM for encryption).

## Glossary

- **Shellock**: The encryption/decryption tool being developed
- **CLI**: Command Line Interface for user interaction
- **API**: Python Application Programming Interface for programmatic access
- **Passphrase**: User-provided secret string used to derive encryption keys
- **Salt**: Random bytes used in key derivation to prevent rainbow table attacks
- **Nonce**: Number used once, random bytes ensuring unique encryption per operation
- **Ciphertext**: Encrypted data output
- **Plaintext**: Original unencrypted data
- **GCM_Tag**: Authentication tag produced by AES-GCM to verify data integrity
- **Envelope**: Binary file format containing header, salt, nonce, tag, and ciphertext
- **KDF**: Key Derivation Function (Argon2id in this case)

## Requirements

### Requirement 1: Key Derivation

**User Story:** As a developer, I want secure key derivation from my passphrase, so that my encryption keys are resistant to brute-force attacks.

#### Acceptance Criteria

1. WHEN a passphrase and salt are provided, THE KDF SHALL derive a 32-byte key using Argon2id
2. WHEN deriving a key, THE KDF SHALL use memory_cost of 65536 (64 MB), time_cost of 2, and parallelism of 4
3. WHEN the same passphrase and salt are provided, THE KDF SHALL produce the same derived key
4. WHEN different salts are provided with the same passphrase, THE KDF SHALL produce different derived keys

### Requirement 2: Encryption

**User Story:** As a developer, I want to encrypt plaintext data with a passphrase, so that my configuration files are protected at rest.

#### Acceptance Criteria

1. WHEN plaintext bytes and a passphrase are provided, THE Encryptor SHALL produce an encrypted envelope
2. WHEN encrypting, THE Encryptor SHALL generate a random 16-byte salt for key derivation
3. WHEN encrypting, THE Encryptor SHALL generate a random 12-byte nonce for AES-GCM
4. WHEN encrypting, THE Encryptor SHALL use AES-256-GCM to produce ciphertext and a 16-byte authentication tag
5. WHEN producing the envelope, THE Encryptor SHALL format it as: magic header (10 bytes) + salt (16 bytes) + nonce (12 bytes) + tag (16 bytes) + ciphertext
6. THE Encryptor SHALL use the magic header value `b"ENVCRYPTv1"` (10 bytes)

### Requirement 3: Decryption

**User Story:** As a developer, I want to decrypt encrypted data with my passphrase, so that I can access my original configuration files.

#### Acceptance Criteria

1. WHEN an encrypted envelope and correct passphrase are provided, THE Decryptor SHALL return the original plaintext bytes
2. WHEN parsing the envelope, THE Decryptor SHALL extract the magic header, salt, nonce, tag, and ciphertext
3. IF the magic header does not match `b"ENVCRYPTv1"`, THEN THE Decryptor SHALL raise an InvalidFileFormat error
4. IF the passphrase is incorrect, THEN THE Decryptor SHALL raise an AuthenticationError
5. IF the ciphertext has been tampered with, THEN THE Decryptor SHALL raise an AuthenticationError

### Requirement 4: Round-Trip Integrity

**User Story:** As a developer, I want encryption and decryption to be reversible, so that I never lose data.

#### Acceptance Criteria

1. FOR ALL valid plaintext bytes and passphrases, encrypting then decrypting SHALL produce the original plaintext
2. FOR ALL valid plaintext bytes, encrypting with the same passphrase twice SHALL produce different ciphertexts (due to random salt and nonce)

### Requirement 5: File-Based API

**User Story:** As a developer, I want to encrypt and decrypt files using a Python API, so that I can integrate EnvCrypt into my scripts and automation.

#### Acceptance Criteria

1. WHEN `encrypt_file(in_path, out_path, passphrase)` is called, THE API SHALL read the input file, encrypt its contents, and write the envelope to the output path
2. WHEN `decrypt_file(in_path, out_path, passphrase)` is called, THE API SHALL read the encrypted file, decrypt its contents, and write the plaintext to the output path
3. IF the input file does not exist, THEN THE API SHALL raise a FileNotFoundError
4. IF the output directory does not exist, THEN THE API SHALL raise a FileNotFoundError

### Requirement 6: CLI Encrypt Command

**User Story:** As a developer, I want to encrypt files from the command line, so that I can quickly protect my configuration files.

#### Acceptance Criteria

1. WHEN `shellock encrypt INPUT --out OUTPUT --passphrase PASS` is executed, THE CLI SHALL encrypt the input file and write to the output path
2. WHEN the `--passphrase` flag is omitted, THE CLI SHALL prompt for the passphrase using secure input (no echo)
3. IF the input file does not exist, THEN THE CLI SHALL exit with a non-zero code and display an error message
4. WHEN encryption succeeds, THE CLI SHALL exit with code 0

### Requirement 7: CLI Decrypt Command

**User Story:** As a developer, I want to decrypt files from the command line, so that I can access my protected configuration files.

#### Acceptance Criteria

1. WHEN `shellock decrypt INPUT --out OUTPUT --passphrase PASS` is executed, THE CLI SHALL decrypt the input file and write to the output path
2. WHEN the `--passphrase` flag is omitted, THE CLI SHALL prompt for the passphrase using secure input (no echo)
3. IF the passphrase is incorrect or the file is tampered, THEN THE CLI SHALL exit with a non-zero code and display an error message
4. IF the file format is invalid, THEN THE CLI SHALL exit with a non-zero code and display an error message
5. WHEN decryption succeeds, THE CLI SHALL exit with code 0

### Requirement 8: CLI Generate-Key Command

**User Story:** As a developer, I want to generate encryption keys, so that I can use both symmetric and asymmetric encryption workflows.

#### Acceptance Criteria

1. WHEN `shellock generate-key --type symmetric --out PATH` is executed, THE CLI SHALL generate 32 random bytes
2. WHEN `shellock generate-key --type asymmetric --out PATH` is executed, THE CLI SHALL generate an Ed25519 keypair
3. WHEN writing symmetric keys, THE CLI SHALL encode them as base64 and write to the specified path
4. WHEN writing asymmetric keys, THE CLI SHALL write the private key in PEM format and display the public key
5. WHEN key generation succeeds, THE CLI SHALL exit with code 0

### Requirement 9: Asymmetric Encryption

**User Story:** As a developer, I want to encrypt files with public keys, so that only the private key holder can decrypt them without sharing passphrases.

#### Acceptance Criteria

1. WHEN `shellock encrypt-public INPUT --key PUBLIC_KEY --out OUTPUT` is executed, THE CLI SHALL encrypt using hybrid encryption
2. WHEN encrypting with public key, THE Encryptor SHALL generate a random symmetric key and encrypt data with AES-256-GCM
3. WHEN encrypting with public key, THE Encryptor SHALL encrypt the symmetric key with the recipient's Ed25519 public key
4. WHEN `shellock decrypt-private INPUT --key PRIVATE_KEY --out OUTPUT` is executed, THE CLI SHALL decrypt using the private key
5. WHEN decrypting with private key, THE Decryptor SHALL first decrypt the symmetric key, then decrypt the data

### Requirement 11: Symmetric Key-Based Encryption

**User Story:** As a developer, I want to encrypt files with pre-generated symmetric keys, so that I can separate key generation from encryption operations.

#### Acceptance Criteria

1. WHEN `shellock encrypt-key INPUT --key KEY_FILE --out OUTPUT` is executed, THE CLI SHALL encrypt using the symmetric key from the file
2. WHEN `shellock decrypt-key INPUT --key KEY_FILE --out OUTPUT` is executed, THE CLI SHALL decrypt using the symmetric key from the file
3. WHEN encrypting with symmetric key file, THE Encryptor SHALL read the base64-encoded key and use it directly for AES-256-GCM encryption
4. WHEN decrypting with symmetric key file, THE Decryptor SHALL read the base64-encoded key and use it directly for AES-256-GCM decryption
5. IF the key file does not exist or is invalid, THEN THE CLI SHALL exit with a non-zero code and display an error message

### Requirement 12: CLI Help

**User Story:** As a developer, I want helpful CLI documentation, so that I can understand how to use the tool.

#### Acceptance Criteria

1. WHEN `shellock --help` is executed, THE CLI SHALL display usage information for all commands
2. WHEN `shellock encrypt --help` is executed, THE CLI SHALL display usage information for the encrypt command
3. WHEN `shellock decrypt --help` is executed, THE CLI SHALL display usage information for the decrypt command
4. WHEN `shellock generate-key --help` is executed, THE CLI SHALL display usage information for the generate-key command
5. WHEN `shellock encrypt-public --help` is executed, THE CLI SHALL display usage information for the encrypt-public command
6. WHEN `shellock decrypt-private --help` is executed, THE CLI SHALL display usage information for the decrypt-private command
7. WHEN `shellock encrypt-key --help` is executed, THE CLI SHALL display usage information for the encrypt-key command
8. WHEN `shellock decrypt-key --help` is executed, THE CLI SHALL display usage information for the decrypt-key command
