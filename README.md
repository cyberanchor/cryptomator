# cryptomotor

![Version](https://img.shields.io/badge/version-2.6-green)   ![Python](https://img.shields.io/badge/python-3.6%2B-green)   ![Last Commit](https://img.shields.io/github/last-commit/cyberanchor/cryptomator)   ![Issues](https://img.shields.io/github/issues/cyberanchor/cryptomator)

**cryptomotor** - cross-platform command-line tool for single file encryption and decryption, utilizing AES-256-GCM, HMAC-SHA512, and Argon2id for key derivation.
Optimized for large files (>4 GB), it supports streaming I/O, memory-mapped files, and detailed system block analysis, ensuring robust security and performance.

## Features
- **File Encryption/Decryption**: Encrypts files with AES-256-GCM and stores metadata in a 780-byte system block, with HMAC-SHA512 for integrity and authenticity.
- **Key Derivation**: Uses Argon2id with configurable memory (4 GB default, 64 MB low-memory mode), 8 iterations, and 8 parallel threads.
- **Large File Support**: Optimized for files >4 GB with streaming I/O and optional memory-mapped file access (--mmap).
- **System Block Analysis**: Provides detailed inspection of encrypted file metadata, including signature, salt, nonce, and HMAC.
- **Flexible Password Input**: Supports passwords via command-line, file, or interactive prompt (UTF-8, up to 4096 characters recommended).
- **Unicode Support**: Handles filenames up to 255 bytes in UTF-8 encoding.
- **Logging**: Detailed, colorized console output.
- **Security**: Validates inputs, enforces minimum file size (4 bytes), and ensures compatibility checks for older file formats.

## Cryptographic Architecture
- **Key Derivation**: Derives a 256-bit AES key using Argon2id with a 64-byte random salt, 4 GB memory (or 64 MB in low-memory mode), 8 iterations, and 8 parallel threads.
- **Encryption**: Encrypts file payload, filename, and SHA-512 hash with AES-256-GCM, using a 16-byte random nonce.
- **Integrity and Authenticity**: Computes HMAC-SHA512 over the payload, padded filename, and hash, stored in the system block.
- **System Block (780 bytes)**:
  - Signature: 8 bytes (`CRYPTv2`, hex: `43525950547632`).
  - Salt: 64 bytes (random, for Argon2id).
  - Nonce: 16 bytes (random, for AES-256-GCM).
  - HMAC: 64 bytes (SHA512, signs payload + padded filename + hash).
  - Encrypted Filename Length: 4 bytes (big-endian, always 496).
  - Encrypted Filename: 512 bytes (496-byte padded filename + 16-byte GCM tag).
  - Encrypted Hash: 80 bytes (64-byte SHA-512 hash + 16-byte GCM tag).
  - Original Filename Length: 4 bytes (big-endian, up to 255).
- **File Format**: `[system_block][encrypted_payload]`.
- **Hashing**: Computes SHA-512 hash of input files for verification during decryption.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/cyberanchor/cryptomator
   cd cryptomator
   ```
2. Install dependencies:
   ```bash
   pip install cryptography argon2-cffi colorama psutil
   ```
3. Run the tool:
   ```bash
   python crypt.argon2.py --help
   ```

## Usage
### Command-Line Arguments
- `--encrypt`: Encrypt files in the specified folder or a single file.
- `--decrypt`: Decrypt files in the specified folder or a single file.
- `--analyze`: Analyze the system block of an encrypted file.
- `--folder <path>`: Folder to process (required for `--encrypt` or `--decrypt`).
- `--file <path>`: Single file to process or analyze.
- `--password <pass>`: Password for encryption/decryption.
- `--password-file <file>`: File containing the password (UTF-8).
- `--debug`: Enable detailed debug output for system block information.
- `--verbose`: Enable verbose console output.
- `--low-memory`: Use lower memory settings for Argon2id (64 MB instead of 4 GB).
- `--dry-run`: Simulate operations without writing files.
- `--force`: Ignore compatibility warnings for older file formats.
- `--mmap`: Use memory-mapped files for large files (>4 GB, requires sufficient memory).

### Examples
1. Encrypt all files in a folder:
   ```bash
   python crypt.argon2.py --encrypt --folder ./data --password mypass --verbose
   ```
   **Output**:
   ```
   cryptomator v2.6
   Processing encrypt in ./data (5 files), output: ./data/encrypted
   Encrypted ./data/file1.txt to ./data/encrypted/abc123... in 0.45s
   ...
   Completed encrypt in ./data: processed 5/5 files in 2.31s
   ```

2. Decrypt a single file:
   ```bash
   python crypt.argon2.py --decrypt --file ./encrypted/abc123 --password-file ./pass.txt
   ```
   **Output**:
   ```
   Decrypted ./encrypted/abc123 to ./decrypted/file1.txt in 0.38s
   ```

3. Analyze an encrypted file’s system block:
   ```bash
   python crypt.argon2.py --analyze --file ./encrypted/abc123 --debug
   ```
   **Output**:
   ```
   Analysis of ./encrypted/abc123:
   File size: 123456 bytes
   System block (780 bytes):
     Offset 0: Signature (8 bytes): 43525950547632
     Offset 8: Salt (64 bytes): 1a2b3c...
     Offset 72: Nonce (16 bytes): 4d5e6f...
     Offset 88: HMAC (64 bytes): 7a8b9c...
     ...
   Encrypted payload: 122676 bytes
   ```

4. Encrypt a large file with memory-mapped I/O:
   ```bash
   python crypt.argon2.py --encrypt --file ./large.bin --password mypass --mmap
   ```

## File Format
Encrypted files follow this structure:
```
[system_block (780 bytes)][encrypted_payload]
```
**System Block Details**:
- Signature: `CRYPTv2` (8 bytes).
- Salt: Random 64 bytes for Argon2id.
- Nonce: Random 16 bytes for AES-256-GCM.
- HMAC: 64-byte SHA512 HMAC of payload + padded filename + hash.
- Filename Length: 4 bytes (always 496).
- Encrypted Filename: 512 bytes (496-byte padded filename + 16-byte GCM tag).
- Encrypted Hash: 80 bytes (64-byte SHA-512 hash + 16-byte GCM tag).
- Original Filename Length: 4 bytes (up to 255).

## Changelog
### Version 2.6 (2025-04-25)
- **Added**: Support for memory-mapped I/O (`--mmap`) for large files (>4 GB), improving performance on high-memory systems.
- **Added**: Detailed system block analysis with `--analyze` and `--debug` options.
- **Improved**: Optimized streaming I/O for large files with dynamic buffer sizes (512 KB for low-memory, 1 MB default).
- **Improved**: Enhanced logging with file rotation (10 MB max, 3 backups) and dependency version reporting.
- **Fixed**: Improved Unicode filename handling (up to 255 bytes in UTF-8).
- **Docs**: Comprehensive README with cryptographic details, examples, and security recommendations.

### Version 2.5
- Transitioned to HMAC-SHA512 (64 bytes) for improved integrity checks.
- Increased system block size to 780 bytes for additional metadata.
- Added compatibility checks for older file formats (`CRYPTv1`).

### Version 2.4
- Introduced Argon2id key derivation with 4 GB memory and 8 parallel threads.
- Added support for low-memory mode (64 MB) with `--low-memory`.
- Improved error handling for large files and memory constraints.

### Version 2.3
- Standardized AES-256-GCM encryption with 16-byte nonce.
- Added streaming I/O for files >1 GB to reduce memory usage.
- Introduced verbose output with `--verbose`.

## Contributing
Submit issues or pull requests.

## Disclaimer
**cryptomator is intended exclusively for personal, lawful use.** The tool is provided for secure file encryption and decryption by individual users. The author and contributors are not responsible for any misuse of this software, including but not limited to its use in malicious, illegal, or harmful activities.
