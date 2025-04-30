#!/usr/bin/env python3
"""
Crypt-Argon2 - A cross-platform file encryption/decryption tool (OOP fork with Argon2id, v2.5).

Overview:
- Encrypts files using AES-256-GCM, HMAC-SHA512, and Argon2id for key derivation.
- Stores metadata (filename, hash) in a 780-byte system block with a signature.
- Supports decryption with integrity and authenticity checks via HMAC-SHA512.
- Provides detailed analysis of encrypted file system blocks.
- Features comprehensive logging with file rotation and colored console output.
- Handles Unicode filenames (up to 255 bytes in UTF-8).
- Enforces a minimum file size of 4 bytes for encryption.
- Supports password input via command-line, file, or interactive prompt.

WARNING: Version 2.5 is not compatible with files encrypted by versions <2.3 due to
changes in HMAC (SHA512, 64 bytes) and system block size (780 bytes).

Dependencies:
- Python 3.6+
- cryptography (pip install cryptography)
- argon2-cffi (pip install argon2-cffi)
- colorama (pip install colorama)

Usage:
    python crypt.argon2.py --encrypt --folder ./path --password mypass --verbose
    python crypt.argon2.py --decrypt --folder ./path --password-file ./pass.txt
    python crypt.argon2.py --analyze --file ./path/file --debug
    python crypt.argon2.py --dry-run --encrypt --folder ./path --password mypass

System Block (780 bytes):
- Signature: 8 bytes ('CRYPTv2', hex: 43525950547632)
- Salt: 64 bytes (random, for Argon2id key derivation)
- Nonce: 16 bytes (random, for AES-256-GCM)
- HMAC: 64 bytes (SHA512, signs data + padded_filename + hash)
- Encrypted Filename Length: 4 bytes (big-endian, always 496)
- Encrypted Filename: 512 bytes (496-byte padded filename + 16-byte GCM tag)
- Encrypted Hash: 80 bytes (64-byte SHA-512 hash + 16-byte GCM tag)
- Original Filename Length: 4 bytes (big-endian, up to 255)

File Format: [system_block][encrypted_payload]

Password Handling:
- Sources: --password, --password-file, or interactive prompt.
- Encoding: UTF-8.
- Max Length: Recommended 4096 characters (UTF-8). Longer passwords are supported with a warning.
- File Input: Password read from file, stripped of whitespace.

Mini-RFC: Crypt-Argon2 File Encryption Protocol
- Version: 2.5
- Date: April 25, 2025
- Overview: Defines a secure method for file encryption/decryption with Argon2id.
- File Format: 780-byte system block with signature + encrypted payload.
- Encryption: AES-256-GCM with Argon2id-derived key, HMAC-SHA512 for integrity.
- Password: Supports command-line, file, or prompt; max recommended length 4096 characters.

"""
import argparse
import getpass
import glob
import logging
import os
import secrets
import hashlib
import struct
import string
import time
import pkg_resources
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from logging.handlers import RotatingFileHandler
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type
from colorama import init, Fore, Style

# Initialize colorama for colored console output
init(autoreset=True)

# Program metadata
PROGRAM_VERSION = "2.5"
PROGRAM_NAME = "Crypt-Argon2"
COMPATIBILITY_WARNING = (
    f"{Fore.YELLOW}WARNING: Version {PROGRAM_VERSION} is not compatible with files encrypted "
    "by versions <2.3 due to changes in HMAC (SHA512, 64 bytes) and system block size (780 bytes)."
    f"{Style.RESET_ALL}"
)

@dataclass(frozen=True)
class CryptConfig:
    """Configuration constants for Crypt-Argon2."""
    SIGNATURE: bytes = b'CRYPTv2'  # 8-byte file signature for version 2
    OLD_SIGNATURE: bytes = b'CRYPTv1'  # Signature for older versions (incompatible)
    SALT_LENGTH: int = 64  # Bytes for random salt used in Argon2id
    NONCE_LENGTH: int = 16  # Bytes for AES-256-GCM nonce
    HMAC_LENGTH: int = 64  # Bytes for SHA512 HMAC
    FILENAME_LENGTH_FIELD: int = 4  # Bytes for encrypted filename length field
    ENCRYPTED_FILENAME_LENGTH: int = 512  # Bytes (496 + 16 GCM tag) for encrypted filename
    ENCRYPTED_HASH_LENGTH: int = 80  # Bytes (64 + 16 GCM tag) for encrypted file hash
    ORIGINAL_FILENAME_LENGTH_FIELD: int = 4  # Bytes for original filename length
    SYSTEM_BLOCK_LENGTH: int = (
        len(SIGNATURE) + SALT_LENGTH + NONCE_LENGTH + HMAC_LENGTH + FILENAME_LENGTH_FIELD +
        ENCRYPTED_FILENAME_LENGTH + ENCRYPTED_HASH_LENGTH + ORIGINAL_FILENAME_LENGTH_FIELD
    )  # Total system block size: 780 bytes
    MIN_FILE_SIZE: int = 4  # Minimum input file size for encryption (bytes)
    MAX_FILENAME_LENGTH: int = 255  # Maximum filename length (bytes, UTF-8)
    MAX_PASSWORD_LENGTH: int = 4096  # Recommended max password length (characters)
    PADDED_FILENAME_LENGTH: int = 496  # Padded filename length for encryption
    RANDOM_FILENAME_LENGTH: int = 32  # Length of random output filenames
    FILENAME_CHARS: str = string.ascii_letters + string.digits + '+=-_*@'  # Allowed characters for random filenames
    ARGON2_MEMORY: int = 4 * 1024 * 1024  # 4 GB memory for Argon2id (default)
    ARGON2_MEMORY_LOW: int = 64 * 1024  # 64 MB for low-memory systems
    ARGON2_ITERATIONS: int = 8  # Number of Argon2id iterations
    ARGON2_PARALLELISM: int = 8  # Parallelism for Argon2id
    LOG_MAX_SIZE: int = 10 * 1024 * 1024  # Max log file size (10 MB)
    LOG_BACKUP_COUNT: int = 3  # Number of backup log files

class CryptKeyManager:
    """Manages cryptographic key derivation, HMAC computation, and random data generation."""
    def __init__(self, config: CryptConfig, low_memory: bool = False):
        """
        Initialize the key manager with configuration and memory settings.

        Args:
            config: CryptConfig instance with program constants.
            low_memory: If True, use lower memory settings for Argon2id (64 MB).
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.memory_cost = self.config.ARGON2_MEMORY_LOW if low_memory else self.config.ARGON2_MEMORY
        self.logger.debug(
            f"Initialized CryptKeyManager: memory_cost={self.memory_cost} KB, "
            f"iterations={self.config.ARGON2_ITERATIONS}, parallelism={self.config.ARGON2_PARALLELISM}"
        )

    def generate_salt(self) -> bytes:
        """
        Generate a cryptographically secure random salt for Argon2id.

        Returns:
            bytes: Random salt of length SALT_LENGTH.

        Raises:
            ValueError: If salt generation fails.
        """
        try:
            salt = secrets.token_bytes(self.config.SALT_LENGTH)
            self.logger.debug(f"Generated salt: {salt.hex()}")
            return salt
        except Exception as e:
            self.logger.error(f"Failed to generate salt: {e}")
            raise ValueError(f"Error generating salt: {e}")

    def generate_nonce(self) -> bytes:
        """
        Generate a cryptographically secure random nonce for AES-256-GCM.

        Returns:
            bytes: Random nonce of length NONCE_LENGTH.

        Raises:
            ValueError: If nonce generation fails.
        """
        try:
            nonce = secrets.token_bytes(self.config.NONCE_LENGTH)
            self.logger.debug(f"Generated nonce: {nonce.hex()}")
            return nonce
        except Exception as e:
            self.logger.error(f"Failed to generate nonce: {e}")
            raise ValueError(f"Error generating nonce: {e}")

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a 256-bit AES key from a password using Argon2id.

        Args:
            password: Password string (UTF-8 encoded).
            salt: Random salt for key derivation.

        Returns:
            bytes: Derived 32-byte key.

        Raises:
            ValueError: If key derivation fails or memory is insufficient.
        """
        self.logger.debug(f"Deriving key with salt: {salt.hex()}")
        try:
            key = hash_secret_raw(
                secret=password.encode('utf-8'),
                salt=salt,
                time_cost=self.config.ARGON2_ITERATIONS,
                memory_cost=self.memory_cost,
                parallelism=self.config.ARGON2_PARALLELISM,
                hash_len=32,
                type=Type.ID
            )
            self.logger.debug(f"Derived key: {key.hex()}")
            return key
        except MemoryError as e:
            self.logger.error(f"Memory error during key derivation: {e}")
            raise ValueError("Insufficient memory for key derivation. Try --low-memory option.")
        except Exception as e:
            self.logger.error(f"Key derivation failed: {e}")
            raise ValueError(f"Error deriving key: {e}")

    def compute_hmac(self, data: bytes, key: bytes, salt: bytes) -> bytes:
        """
        Compute HMAC-SHA512 of data with a key and salt.

        Args:
            data: Data to sign.
            key: HMAC key.
            salt: Salt to prepend to data.

        Returns:
            bytes: 64-byte HMAC-SHA512 value.

        Raises:
            ValueError: If HMAC computation fails.
        """
        self.logger.debug(f"Computing HMAC-SHA512 with salt: {salt.hex()}")
        try:
            h = hmac.HMAC(key, hashes.SHA512())
            h.update(salt + data)
            hmac_value = h.finalize()
            self.logger.debug(f"Computed HMAC-SHA512: {hmac_value.hex()}")
            return hmac_value
        except Exception as e:
            self.logger.error(f"HMAC computation failed: {e}")
            raise ValueError(f"Error computing HMAC: {e}")

    def compute_file_hash(self, file_path: Path) -> bytes:
        """
        Compute SHA-512 hash of a file's contents.

        Args:
            file_path: Path to the file.

        Returns:
            bytes: 64-byte SHA-512 hash.

        Raises:
            ValueError: If file cannot be read.
        """
        self.logger.debug(f"Computing SHA-512 hash for: {file_path}")
        try:
            sha512 = hashlib.sha512()
            with file_path.open('rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha512.update(chunk)
            hash_value = sha512.digest()
            self.logger.debug(f"Computed SHA-512 hash: {hash_value.hex()}")
            return hash_value
        except (IOError, PermissionError) as e:
            self.logger.error(f"Failed to read file for hashing {file_path}: {e}")
            raise ValueError(f"Error reading file {file_path}: {e}")

class CryptFileProcessor:
    """Handles file encryption, decryption, and system block analysis."""
    def __init__(self, config: CryptConfig, low_memory: bool = False, verbose: bool = False):
        """
        Initialize the file processor with configuration and options.

        Args:
            config: CryptConfig instance with program constants.
            low_memory: If True, use lower memory settings for Argon2id.
            verbose: If True, enable verbose console output.
        """
        self.config = config
        self.key_manager = CryptKeyManager(config, low_memory)
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"Initialized CryptFileProcessor: low_memory={low_memory}, verbose={verbose}")

    def _validate_password(self, password: str) -> None:
        """
        Validate the password length and emptiness.

        Args:
            password: Password to validate.

        Raises:
            ValueError: If password is empty or invalid.
        """
        try:
            if not password:
                raise ValueError("Password cannot be empty")
            if len(password) > self.config.MAX_PASSWORD_LENGTH:
                warning = (
                    f"Password length ({len(password)} characters) exceeds recommended maximum "
                    f"({self.config.MAX_PASSWORD_LENGTH} characters). Processing will continue, but performance may be affected."
                )
                self.logger.warning(warning)
                print(f"{Fore.YELLOW}Warning: {warning}{Style.RESET_ALL}")
        except Exception as e:
            self.logger.error(f"Password validation failed: {e}")
            raise ValueError(f"Error validating password: {e}")

    def _generate_random_filename(self) -> str:
        """
        Generate a random filename using allowed characters.

        Returns:
            str: Random filename of length RANDOM_FILENAME_LENGTH.

        Raises:
            ValueError: If filename generation fails.
        """
        try:
            filename = ''.join(secrets.choice(self.config.FILENAME_CHARS) for _ in range(self.config.RANDOM_FILENAME_LENGTH))
            self.logger.debug(f"Generated random filename: {filename}")
            return filename
        except Exception as e:
            self.logger.error(f"Failed to generate random filename: {e}")
            raise ValueError(f"Error generating filename: {e}")

    def _read_file(self, file_path: Path) -> bytes:
        """
        Read file content with permission and existence checks.

        Args:
            file_path: Path to the file.

        Returns:
            bytes: File contents.

        Raises:
            ValueError: If file cannot be read or permissions are insufficient.
        """
        try:
            if not file_path.is_file():
                raise ValueError(f"{file_path} is not a file")
            if not os.access(file_path, os.R_OK):
                raise PermissionError(f"No read permission for {file_path}")
            with file_path.open('rb') as f:
                data = f.read()
            self.logger.debug(f"Read {len(data)} bytes from {file_path}")
            if self.verbose:
                print(f"{Fore.CYAN}Read {len(data)} bytes from {file_path}{Style.RESET_ALL}")
            return data
        except (IOError, PermissionError) as e:
            self.logger.error(f"Failed to read file {file_path}: {e}")
            raise ValueError(f"Error reading file {file_path}: {e}")

    def _write_file(self, file_path: Path, data: bytes) -> None:
        """
        Write data to a file with permission and directory checks.

        Args:
            file_path: Path to write the file.
            data: Data to write.

        Raises:
            ValueError: If file cannot be written or permissions are insufficient.
        """
        try:
            if not os.access(file_path.parent, os.W_OK):
                raise PermissionError(f"No write permission for {file_path.parent}")
            if file_path.exists():
                self.logger.warning(f"Overwriting existing file: {file_path}")
                print(f"{Fore.YELLOW}Warning: Overwriting {file_path}{Style.RESET_ALL}")
            with file_path.open('wb') as f:
                f.write(data)
            self.logger.debug(f"Wrote {len(data)} bytes to {file_path}")
            if self.verbose:
                print(f"{Fore.CYAN}Wrote {len(data)} bytes to {file_path}{Style.RESET_ALL}")
        except (IOError, PermissionError) as e:
            self.logger.error(f"Failed to write file {file_path}: {e}")
            raise ValueError(f"Error writing file {file_path}: {e}")

    def encrypt_file(self, input_file: str, output_dir: str, password: str, debug: bool = False, dry_run: bool = False) -> None:
        """
        Encrypt a file with AES-256-GCM and store metadata in a system block.

        Args:
            input_file: Path to the input file.
            output_dir: Directory for the encrypted file.
            password: Password for encryption.
            debug: If True, print detailed system block information.
            dry_run: If True, simulate encryption without writing files.

        Raises:
            ValueError: If encryption fails or input is invalid.
        """
        input_path = Path(input_file)
        output_path = Path(output_dir)
        start_time = time.time()
        try:
            self.logger.info(f"Starting encryption of {input_path}")
            if self.verbose:
                print(f"{Fore.CYAN}Encrypting {input_path}...{Style.RESET_ALL}")
            self._validate_password(password)
            file_size = input_path.stat().st_size
            if file_size < self.config.MIN_FILE_SIZE:
                raise ValueError(f"File {input_path} is too small (< {self.config.MIN_FILE_SIZE} bytes)")

            input_hash = self.key_manager.compute_file_hash(input_path)
            if self.verbose:
                print(f"{Fore.CYAN}Input SHA-512 hash: {input_hash.hex()[:32]}...{Style.RESET_ALL}")

            data = self._read_file(input_path)
            original_hash = input_hash
            filename = input_path.name.encode('utf-8')
            if len(filename) > self.config.MAX_FILENAME_LENGTH:
                raise ValueError(f"Filename {input_path} exceeds {self.config.MAX_FILENAME_LENGTH} bytes")
            original_filename_length = len(filename)

            salt = self.key_manager.generate_salt()
            key = self.key_manager.derive_key(password, salt)
            nonce = self.key_manager.generate_nonce()
            aesgcm = AESGCM(key)

            ciphertext = aesgcm.encrypt(nonce, data, None)
            padded_filename = filename + b'\x00' * (self.config.PADDED_FILENAME_LENGTH - len(filename))
            encrypted_filename = aesgcm.encrypt(nonce, padded_filename, None)
            encrypted_hash = aesgcm.encrypt(nonce, original_hash, None)

            hmac_input = data + padded_filename + original_hash
            hmac_value = self.key_manager.compute_hmac(hmac_input, key, salt)

            system_block = (
                self.config.SIGNATURE +
                salt +
                nonce +
                hmac_value +
                struct.pack('>I', self.config.PADDED_FILENAME_LENGTH) +
                encrypted_filename +
                encrypted_hash +
                struct.pack('>I', original_filename_length)
            )
            if len(system_block) != self.config.SYSTEM_BLOCK_LENGTH:
                raise ValueError(
                    f"System block length mismatch: {len(system_block)} bytes, expected {self.config.SYSTEM_BLOCK_LENGTH}"
                )

            output_filename = self._generate_random_filename()
            output_file = output_path / output_filename
            output_data = system_block + ciphertext

            if dry_run:
                self.logger.info(f"Dry run: Would encrypt {input_path} to {output_file} ({len(output_data)} bytes)")
                print(f"{Fore.YELLOW}Dry run: Would encrypt {input_path} to {output_file} ({len(output_data)} bytes){Style.RESET_ALL}")
                return

            self._write_file(output_file, output_data)

            if debug:
                self._print_debug_system_block(
                    output_filename, salt, nonce, hmac_value,
                    self.config.PADDED_FILENAME_LENGTH, encrypted_filename, encrypted_hash,
                    original_filename_length
                )
            elif self.verbose:
                print(f"{Fore.CYAN}System block: {self.config.SYSTEM_BLOCK_LENGTH} bytes, HMAC: {hmac_value.hex()[:32]}...{Style.RESET_ALL}")

            elapsed_time = time.time() - start_time
            self.logger.info(
                f"Encrypted {input_path} to {output_file} in {elapsed_time:.2f}s, "
                f"input_hash={input_hash.hex()[:16]}..."
            )
            print(f"{Fore.GREEN}Encrypted {input_path} to {output_file} in {elapsed_time:.2f}s{Style.RESET_ALL}")
        except Exception as e:
            self.logger.error(f"Encryption failed for {input_path}: {e}")
            print(f"{Fore.RED}Error encrypting {input_path}: {e}{Style.RESET_ALL}")
            raise

    def decrypt_file(self, encrypted_file: str, output_dir: str, password: str, debug: bool = False, dry_run: bool = False) -> None:
        """
        Decrypt a file and verify integrity using system block metadata.

        Args:
            encrypted_file: Path to the encrypted file.
            output_dir: Directory for the decrypted file.
            password: Password for decryption.
            debug: If True, print detailed system block information.
            dry_run: If True, simulate decryption without writing files.

        Raises:
            ValueError: If decryption fails or file is invalid.
        """
        encrypted_path = Path(encrypted_file)
        output_path = Path(output_dir)
        temp_path = None
        start_time = time.time()
        try:
            self.logger.info(f"Starting decryption of {encrypted_path}")
            if self.verbose:
                print(f"{Fore.CYAN}Decrypting {encrypted_path}...{Style.RESET_ALL}")
            self._validate_password(password)
            data = self._read_file(encrypted_path)
            if len(data) < self.config.SYSTEM_BLOCK_LENGTH:
                raise ValueError(
                    f"File {encrypted_path} too short ({len(data)} bytes, expected at least {self.config.SYSTEM_BLOCK_LENGTH})"
                )
            if data[:len(self.config.SIGNATURE)] == self.config.OLD_SIGNATURE:
                raise ValueError(
                    f"File {encrypted_path} uses old signature ({self.config.OLD_SIGNATURE.decode()}). "
                    f"Version {PROGRAM_VERSION} is incompatible with files from versions <2.3."
                )
            if data[:len(self.config.SIGNATURE)] != self.config.SIGNATURE:
                raise ValueError(f"Invalid file signature in {encrypted_path}")

            offset = 0
            signature = data[offset:offset + len(self.config.SIGNATURE)]
            offset += len(self.config.SIGNATURE)

            if len(data) < offset + self.config.SALT_LENGTH:
                raise ValueError(f"File too short for salt at offset {offset}")
            salt = data[offset:offset + self.config.SALT_LENGTH]
            offset += self.config.SALT_LENGTH

            if len(data) < offset + self.config.NONCE_LENGTH:
                raise ValueError(f"File too short for nonce at offset {offset}")
            nonce = data[offset:offset + self.config.NONCE_LENGTH]
            offset += self.config.NONCE_LENGTH

            if len(data) < offset + self.config.HMAC_LENGTH:
                raise ValueError(f"File too short for HMAC at offset {offset}")
            stored_hmac = data[offset:offset + self.config.HMAC_LENGTH]
            offset += self.config.HMAC_LENGTH

            if len(data) < offset + self.config.FILENAME_LENGTH_FIELD:
                raise ValueError(f"File too short for filename length at offset {offset}")
            try:
                filename_length = struct.unpack('>I', data[offset:offset + self.config.FILENAME_LENGTH_FIELD])[0]
            except struct.error as e:
                raise ValueError(f"Invalid filename length field at offset {offset}: {e}")
            offset += self.config.FILENAME_LENGTH_FIELD

            if len(data) < offset + self.config.ENCRYPTED_FILENAME_LENGTH:
                raise ValueError(f"File too short for encrypted filename at offset {offset}")
            encrypted_filename = data[offset:offset + self.config.ENCRYPTED_FILENAME_LENGTH]
            offset += self.config.ENCRYPTED_FILENAME_LENGTH

            if len(data) < offset + self.config.ENCRYPTED_HASH_LENGTH:
                raise ValueError(f"File too short for encrypted hash at offset {offset}")
            encrypted_hash = data[offset:offset + self.config.ENCRYPTED_HASH_LENGTH]
            offset += self.config.ENCRYPTED_HASH_LENGTH

            if len(data) < offset + self.config.ORIGINAL_FILENAME_LENGTH_FIELD:
                raise ValueError(f"File too short for original filename length at offset {offset}")
            try:
                original_filename_length = struct.unpack('>I', data[offset:offset + self.config.ORIGINAL_FILENAME_LENGTH_FIELD])[0]
            except struct.error as e:
                raise ValueError(f"Invalid original filename length field at offset {offset}: {e}")
            offset += self.config.ORIGINAL_FILENAME_LENGTH_FIELD

            ciphertext = data[offset:]
            if not ciphertext:
                raise ValueError("No encrypted payload found")

            if filename_length != self.config.PADDED_FILENAME_LENGTH:
                raise ValueError(f"Invalid filename length: {filename_length}, expected {self.config.PADDED_FILENAME_LENGTH}")
            if len(encrypted_filename) != self.config.ENCRYPTED_FILENAME_LENGTH:
                raise ValueError(
                    f"Invalid encrypted filename length: {len(encrypted_filename)}, expected {self.config.ENCRYPTED_FILENAME_LENGTH}"
                )
            if len(encrypted_hash) != self.config.ENCRYPTED_HASH_LENGTH:
                raise ValueError(
                    f"Invalid encrypted hash length: {len(encrypted_hash)}, expected {self.config.ENCRYPTED_HASH_LENGTH}"
                )
            if original_filename_length > self.config.MAX_FILENAME_LENGTH:
                raise ValueError(
                    f"Invalid original filename length: {original_filename_length}, max {self.config.MAX_FILENAME_LENGTH}"
                )

            if debug:
                self._print_debug_system_block(
                    str(encrypted_path), salt, nonce, stored_hmac,
                    filename_length, encrypted_filename, encrypted_hash, original_filename_length
                )
            elif self.verbose:
                print(f"{Fore.CYAN}System block: {self.config.SYSTEM_BLOCK_LENGTH} bytes, HMAC: {stored_hmac.hex()[:32]}...{Style.RESET_ALL}")

            key = self.key_manager.derive_key(password, salt)
            aesgcm = AESGCM(key)
            try:
                decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
                decrypted_padded_filename = aesgcm.decrypt(nonce, encrypted_filename, None)
                decrypted_hash = aesgcm.decrypt(nonce, encrypted_hash, None)
            except InvalidTag:
                self.logger.error(f"Decryption failed for {encrypted_path}: Invalid password or corrupted data")
                print(f"{Fore.RED}Decryption failed for {encrypted_path}: Invalid password or corrupted data{Style.RESET_ALL}")
                return

            decrypted_filename = decrypted_padded_filename[:original_filename_length]
            self.logger.debug(f"Decrypted filename: {decrypted_filename.decode('utf-8', errors='ignore')}")

            hmac_input = decrypted_data + decrypted_padded_filename + decrypted_hash
            computed_hmac = self.key_manager.compute_hmac(hmac_input, key, salt)
            if computed_hmac != stored_hmac:
                self.logger.error(f"HMAC verification failed for {encrypted_path}")
                print(f"{Fore.RED}Error: HMAC verification failed for {encrypted_path}{Style.RESET_ALL}")
                return

            if dry_run:
                self.logger.info(
                    f"Dry run: Would decrypt {encrypted_path} to {output_path / decrypted_filename.decode('utf-8', errors='replace')}"
                )
                print(
                    f"{Fore.YELLOW}Dry run: Would decrypt {encrypted_path} to "
                    f"{output_path / decrypted_filename.decode('utf-8', errors='replace')}{Style.RESET_ALL}"
                )
                return

            temp_path = output_path / f"{self._generate_random_filename()}.tmp"
            self._write_file(temp_path, decrypted_data)
            computed_hash = self.key_manager.compute_file_hash(temp_path)
            if computed_hash != decrypted_hash:
                self.logger.error(f"Hash verification failed for {encrypted_path}")
                print(f"{Fore.RED}Error: Hash verification failed for {encrypted_path}{Style.RESET_ALL}")
                with suppress(OSError):
                    temp_path.unlink()
                return

            if self.verbose:
                print(f"{Fore.CYAN}Output SHA-512 hash: {computed_hash.hex()[:32]}...{Style.RESET_ALL}")

            output_filename = decrypted_filename.decode('utf-8', errors='replace')
            final_path = output_path / output_filename
            try:
                temp_path.rename(final_path)
            except OSError as e:
                self.logger.error(f"Failed to rename {temp_path} to {final_path}: {e}")
                print(f"{Fore.RED}Error renaming file to {final_path}: {e}{Style.RESET_ALL}")
                with suppress(OSError):
                    temp_path.unlink()
                return

            elapsed_time = time.time() - start_time
            self.logger.info(
                f"Decrypted {encrypted_path} to {final_path} in {elapsed_time:.2f}s, "
                f"output_hash={computed_hash.hex()[:16]}..."
            )
            print(f"{Fore.GREEN}Decrypted {encrypted_path} to {final_path} in {elapsed_time:.2f}s{Style.RESET_ALL}")
        except Exception as e:
            self.logger.error(f"Decryption failed for {encrypted_path}: {e}")
            print(f"{Fore.RED}Error decrypting {encrypted_path}: {e}{Style.RESET_ALL}")
            if temp_path and temp_path.exists():
                with suppress(OSError):
                    temp_path.unlink()

    def analyze_file(self, file_path: str, debug: bool = False) -> None:
        """
        Analyze the system block of an encrypted file.

        Args:
            file_path: Path to the encrypted file.
            debug: If True, print detailed system block information.

        Raises:
            ValueError: If file is invalid or cannot be read.
        """
        file_path = Path(file_path)
        start_time = time.time()
        try:
            self.logger.info(f"Starting analysis of {file_path}")
            if self.verbose:
                print(f"{Fore.CYAN}Analyzing {file_path}...{Style.RESET_ALL}")
            data = self._read_file(file_path)
            if len(data) < self.config.SYSTEM_BLOCK_LENGTH:
                raise ValueError(
                    f"File {file_path} too short ({len(data)} bytes, expected at least {self.config.SYSTEM_BLOCK_LENGTH})"
                )
            if data[:len(self.config.SIGNATURE)] == self.config.OLD_SIGNATURE:
                raise ValueError(
                    f"File {file_path} uses old signature ({self.config.OLD_SIGNATURE.decode()}). "
                    f"Version {PROGRAM_VERSION} is incompatible with files from versions <2.3."
                )
            if data[:len(self.config.SIGNATURE)] != self.config.SIGNATURE:
                raise ValueError(f"Invalid file signature in {file_path}")

            offset = 0
            signature = data[offset:offset + len(self.config.SIGNATURE)]
            offset += len(self.config.SIGNATURE)

            if len(data) < offset + self.config.SALT_LENGTH:
                raise ValueError(f"File too short for salt at offset {offset}")
            salt = data[offset:offset + self.config.SALT_LENGTH]
            offset += self.config.SALT_LENGTH

            if len(data) < offset + self.config.NONCE_LENGTH:
                raise ValueError(f"File too short for nonce at offset {offset}")
            nonce = data[offset:offset + self.config.NONCE_LENGTH]
            offset += self.config.NONCE_LENGTH

            if len(data) < offset + self.config.HMAC_LENGTH:
                raise ValueError(f"File too short for HMAC at offset {offset}")
            hmac_value = data[offset:offset + self.config.HMAC_LENGTH]
            offset += self.config.HMAC_LENGTH

            if len(data) < offset + self.config.FILENAME_LENGTH_FIELD:
                raise ValueError(f"File too short for filename length at offset {offset}")
            try:
                filename_length = struct.unpack('>I', data[offset:offset + self.config.FILENAME_LENGTH_FIELD])[0]
            except struct.error as e:
                raise ValueError(f"Invalid filename length field at offset {offset}: {e}")
            offset += self.config.FILENAME_LENGTH_FIELD

            if len(data) < offset + self.config.ENCRYPTED_FILENAME_LENGTH:
                raise ValueError(f"File too short for encrypted filename at offset {offset}")
            encrypted_filename = data[offset:offset + self.config.ENCRYPTED_FILENAME_LENGTH]
            offset += self.config.ENCRYPTED_FILENAME_LENGTH

            if len(data) < offset + self.config.ENCRYPTED_HASH_LENGTH:
                raise ValueError(f"File too short for encrypted hash at offset {offset}")
            encrypted_hash = data[offset:offset + self.config.ENCRYPTED_HASH_LENGTH]
            offset += self.config.ENCRYPTED_HASH_LENGTH

            if len(data) < offset + self.config.ORIGINAL_FILENAME_LENGTH_FIELD:
                raise ValueError(f"File too short for original filename length at offset {offset}")
            try:
                original_filename_length = struct.unpack('>I', data[offset:offset + self.config.ORIGINAL_FILENAME_LENGTH_FIELD])[0]
            except struct.error as e:
                raise ValueError(f"Invalid original filename length field at offset {offset}: {e}")
            offset += self.config.ORIGINAL_FILENAME_LENGTH_FIELD

            payload_length = len(data) - self.config.SYSTEM_BLOCK_LENGTH

            print(f"{Fore.CYAN}Analysis of {file_path}:{Style.RESET_ALL}")
            print(f"File size: {len(data)} bytes")
            print(f"System block ({self.config.SYSTEM_BLOCK_LENGTH} bytes):")
            print(f"  Offset 0: Signature ({len(self.config.SIGNATURE)} bytes): {signature.hex()}")
            print(f"  Offset {len(self.config.SIGNATURE)}: Salt ({self.config.SALT_LENGTH} bytes): {salt.hex()[:32]}...")
            print(f"  Offset {len(self.config.SIGNATURE) + self.config.SALT_LENGTH}: Nonce ({self.config.NONCE_LENGTH} bytes): {nonce.hex()}")
            print(f"  Offset {len(self.config.SIGNATURE) + self.config.SALT_LENGTH + self.config.NONCE_LENGTH}: HMAC ({self.config.HMAC_LENGTH} bytes): {hmac_value.hex()[:32]}...")
            print(f"  Offset {len(self.config.SIGNATURE) + self.config.SALT_LENGTH + self.config.NONCE_LENGTH + self.config.HMAC_LENGTH}: Filename length ({self.config.FILENAME_LENGTH_FIELD} bytes): {filename_length}")
            print(f"  Offset {len(self.config.SIGNATURE) + self.config.SALT_LENGTH + self.config.NONCE_LENGTH + self.config.HMAC_LENGTH + self.config.FILENAME_LENGTH_FIELD}: Filename ({self.config.ENCRYPTED_FILENAME_LENGTH} bytes): {encrypted_filename.hex()[:32]}...")
            print(f"  Offset {len(self.config.SIGNATURE) + self.config.SALT_LENGTH + self.config.NONCE_LENGTH + self.config.HMAC_LENGTH + self.config.FILENAME_LENGTH_FIELD + self.config.ENCRYPTED_FILENAME_LENGTH}: Hash ({self.config.ENCRYPTED_HASH_LENGTH} bytes): {encrypted_hash.hex()[:32]}...")
            print(f"  Offset {len(self.config.SIGNATURE) + self.config.SALT_LENGTH + self.config.NONCE_LENGTH + self.config.HMAC_LENGTH + self.config.FILENAME_LENGTH_FIELD + self.config.ENCRYPTED_FILENAME_LENGTH + self.config.ENCRYPTED_HASH_LENGTH}: Original filename length ({self.config.ORIGINAL_FILENAME_LENGTH_FIELD} bytes): {original_filename_length}")
            print(f"Encrypted payload: {payload_length} bytes")

            elapsed_time = time.time() - start_time
            self.logger.info(
                f"Analyzed {file_path} in {elapsed_time:.2f}s: signature={signature.hex()}, salt={salt.hex()[:16]}..., "
                f"nonce={nonce.hex()}, filename_length={filename_length}, "
                f"original_filename_length={original_filename_length}, payload_size={payload_length}"
            )
        except Exception as e:
            self.logger.error(f"Analysis failed for {file_path}: {e}")
            print(f"{Fore.RED}Error analyzing {file_path}: {e}{Style.RESET_ALL}")

    def _print_debug_system_block(
        self, filename: str, salt: bytes, nonce: bytes, hmac_value: bytes,
        filename_length: int, encrypted_filename: bytes, encrypted_hash: bytes,
        original_filename_length: int
    ) -> None:
        """
        Print detailed debug information for the system block.

        Args:
            filename: Name of the file being processed.
            salt: Salt bytes.
            nonce: Nonce bytes.
            hmac_value: HMAC bytes.
            filename_length: Length of the padded filename.
            encrypted_filename: Encrypted filename bytes.
            encrypted_hash: Encrypted hash bytes.
            original_filename_length: Length of the original filename.
        """
        print(f"{Fore.YELLOW}System block for {filename}:{Style.RESET_ALL}")
        print(f"  Offset 0: Signature ({len(self.config.SIGNATURE)} bytes): {self.config.SIGNATURE.hex()}")
        print(f"  Offset {len(self.config.SIGNATURE)}: Salt ({self.config.SALT_LENGTH} bytes): {salt.hex()}")
        print(f"  Offset {len(self.config.SIGNATURE) + self.config.SALT_LENGTH}: Nonce ({self.config.NONCE_LENGTH} bytes): {nonce.hex()}")
        print(f"  Offset {len(self.config.SIGNATURE) + self.config.SALT_LENGTH + self.config.NONCE_LENGTH}: HMAC ({self.config.HMAC_LENGTH} bytes): {hmac_value.hex()}")
        print(f"  Offset {len(self.config.SIGNATURE) + self.config.SALT_LENGTH + self.config.NONCE_LENGTH + self.config.HMAC_LENGTH}: Filename length ({self.config.FILENAME_LENGTH_FIELD} bytes): {filename_length}")
        print(f"  Offset {len(self.config.SIGNATURE) + self.config.SALT_LENGTH + self.config.NONCE_LENGTH + self.config.HMAC_LENGTH + self.config.FILENAME_LENGTH_FIELD}: Filename ({self.config.ENCRYPTED_FILENAME_LENGTH} bytes): {encrypted_filename.hex()[:64]}...")
        print(f"  Offset {len(self.config.SIGNATURE) + self.config.SALT_LENGTH + self.config.NONCE_LENGTH + self.config.HMAC_LENGTH + self.config.FILENAME_LENGTH_FIELD + self.config.ENCRYPTED_FILENAME_LENGTH}: Hash ({self.config.ENCRYPTED_HASH_LENGTH} bytes): {encrypted_hash.hex()}")
        print(f"  Offset {len(self.config.SIGNATURE) + self.config.SALT_LENGTH + self.config.NONCE_LENGTH + self.config.HMAC_LENGTH + self.config.FILENAME_LENGTH_FIELD + self.config.ENCRYPTED_FILENAME_LENGTH + self.config.ENCRYPTED_HASH_LENGTH}: Original filename length ({self.config.ORIGINAL_FILENAME_LENGTH_FIELD} bytes): {original_filename_length}")

    def process_folder(
        self, folder: str, password: str, mode: str = 'encrypt',
        single_file: Optional[str] = None, debug: bool = False, dry_run: bool = False
    ) -> None:
        """
        Process files in a folder or a single file for encryption/decryption.

        Args:
            folder: Path to the folder to process.
            password: Password for encryption/decryption.
            mode: 'encrypt' or 'decrypt'.
            single_file: Optional single file to process.
            debug: If True, print detailed debug output.
            dry_run: If True, simulate processing without writing files.
        """
        folder_path = Path(folder).expanduser()
        output_dir = folder_path / ('encrypted' if mode == 'encrypt' else 'decrypted')
        start_time = time.time()
        processed_files = 0
        try:
            if not folder_path.exists():
                raise ValueError(f"Folder {folder_path} does not exist")
            if not folder_path.is_dir():
                raise ValueError(f"{folder_path} is not a directory")
            output_dir.mkdir(parents=True, exist_ok=True)
            if not os.access(output_dir, os.W_OK):
                raise PermissionError(f"No write permission for {output_dir}")

            file_count = sum(1 for f in folder_path.glob('*') if f.is_file())
            self.logger.info(f"Processing {mode} in folder: {folder_path}, output: {output_dir}, files: {file_count}")
            print(f"{Fore.CYAN}Processing {mode} in {folder_path} ({file_count} files), output: {output_dir}{Style.RESET_ALL}")

            if single_file:
                file_path = folder_path / single_file
                if not file_path.is_file():
                    self.logger.error(f"File {file_path} does not exist")
                    print(f"{Fore.RED}Error: File {file_path} does not exist{Style.RESET_ALL}")
                    return
                if mode == 'encrypt':
                    self.encrypt_file(str(file_path), str(output_dir), password, debug, dry_run)
                    processed_files += 1
                elif mode == 'decrypt':
                    try:
                        with file_path.open('rb') as f:
                            signature = f.read(len(self.config.SIGNATURE))
                        if signature == self.config.SIGNATURE:
                            self.decrypt_file(str(file_path), str(output_dir), password, debug, dry_run)
                            processed_files += 1
                        elif signature == self.config.OLD_SIGNATURE:
                            self.logger.error(
                                f"File {file_path} uses old signature ({self.config.OLD_SIGNATURE.decode()}). "
                                f"Version {PROGRAM_VERSION} is incompatible."
                            )
                            print(
                                f"{Fore.RED}Error: File {file_path} uses old signature. "
                                f"Version {PROGRAM_VERSION} is incompatible with versions <2.3.{Style.RESET_ALL}"
                            )
                        else:
                            self.logger.warning(f"Skipping {file_path}: Not a Crypt-Argon2 file")
                            print(f"{Fore.YELLOW}Skipping {file_path}: Not a Crypt-Argon2 file{Style.RESET_ALL}")
                    except (IOError, PermissionError) as e:
                        self.logger.error(f"Error checking signature for {file_path}: {e}")
                        print(f"{Fore.RED}Error checking {file_path}: {e}{Style.RESET_ALL}")
            else:
                for file in folder_path.glob('*'):
                    if file.is_file():
                        if mode == 'encrypt':
                            self.encrypt_file(str(file), str(output_dir), password, debug, dry_run)
                            processed_files += 1
                        else:
                            try:
                                with file.open('rb') as f:
                                    signature = f.read(len(self.config.SIGNATURE))
                                if signature == self.config.SIGNATURE:
                                    self.decrypt_file(str(file), str(output_dir), password, debug, dry_run)
                                    processed_files += 1
                                elif signature == self.config.OLD_SIGNATURE:
                                    self.logger.error(
                                        f"File {file} uses old signature ({self.config.OLD_SIGNATURE.decode()}). "
                                        f"Version {PROGRAM_VERSION} is incompatible."
                                    )
                                    print(
                                        f"{Fore.RED}Error: File {file} uses old signature. "
                                        f"Version {PROGRAM_VERSION} is incompatible with versions <2.3.{Style.RESET_ALL}"
                                    )
                                else:
                                    self.logger.warning(f"Skipping {file}: Not a Crypt-Argon2 file")
                                    print(f"{Fore.YELLOW}Skipping {file}: Not a Crypt-Argon2 file{Style.RESET_ALL}")
                            except (IOError, PermissionError) as e:
                                self.logger.error(f"Error checking signature for {file}: {e}")
                                print(f"{Fore.RED}Error checking {file}: {e}{Style.RESET_ALL}")

            elapsed_time = time.time() - start_time
            self.logger.info(
                f"Completed {mode} in {folder_path}: processed {processed_files}/{file_count} files in {elapsed_time:.2f}s"
            )
            print(
                f"{Fore.GREEN}Completed {mode} in {folder_path}: "
                f"processed {processed_files}/{file_count} files in {elapsed_time:.2f}s{Style.RESET_ALL}"
            )
        except (OSError, PermissionError, ValueError) as e:
            self.logger.error(f"Failed to process folder {folder_path}: {e}")
            print(f"{Fore.RED}Error processing folder {folder_path}: {e}{Style.RESET_ALL}")

class CryptCLI:
    """Command-line interface for Crypt-Argon2."""
    def __init__(self):
        """Initialize the CLI with configuration and logging."""
        self.config = CryptConfig()
        self.logger = logging.getLogger(__name__)

        # Configure logging with rotation
        log_handler = RotatingFileHandler(
            'crypt.argon2.log',
            maxBytes=self.config.LOG_MAX_SIZE,
            backupCount=self.config.LOG_BACKUP_COUNT
        )
        log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(log_handler)
        self.logger.setLevel(logging.DEBUG)

        # Log program and dependency versions
        try:
            crypto_version = pkg_resources.get_distribution("cryptography").version
            argon2_version = pkg_resources.get_distribution("argon2-cffi").version
            colorama_version = pkg_resources.get_distribution("colorama").version
        except pkg_resources.DistributionNotFound as e:
            self.logger.error(f"Failed to get dependency versions: {e}")
            crypto_version = argon2_version = colorama_version = "unknown"
        self.logger.info(
            f"Starting {PROGRAM_NAME} v{PROGRAM_VERSION}, "
            f"dependencies: cryptography={crypto_version}, argon2-cffi={argon2_version}, colorama={colorama_version}"
        )

    def _read_password_from_file(self, file_path: str) -> str:
        """
        Read a password from a file, stripping whitespace.

        Args:
            file_path: Path to the password file.

        Returns:
            str: Password string.

        Raises:
            ValueError: If file cannot be read or is invalid.
        """
        file_path = Path(file_path)
        try:
            if not file_path.is_file():
                raise ValueError(f"Password file {file_path} does not exist")
            if not os.access(file_path, os.R_OK):
                raise PermissionError(f"No read permission for {file_path}")
            with file_path.open('r', encoding='utf-8') as f:
                password = f.read().strip()
            self.logger.debug(f"Read password from file: {file_path} (length: {len(password)} characters)")
            return password
        except (IOError, PermissionError, UnicodeDecodeError) as e:
            self.logger.error(f"Failed to read password from {file_path}: {e}")
            raise ValueError(f"Error reading password file {file_path}: {e}")

    def _print_startup_info(self, args: argparse.Namespace) -> None:
        """Print startup information to the console."""
        print(f"{Fore.CYAN}{PROGRAM_NAME} v{PROGRAM_VERSION}{Style.RESET_ALL}")
        print(COMPATIBILITY_WARNING)
        print(f"Mode: {'encrypt' if args.encrypt else 'decrypt' if args.decrypt else 'analyze'}")
        if args.folder:
            folder_path = Path(args.folder).expanduser()
            file_count = sum(1 for f in folder_path.glob('*') if f.is_file())
            print(f"Folder: {folder_path} ({file_count} files)")
        if args.file:
            print(f"File: {Path(args.file).expanduser()}")
        print(f"Argon2id: memory={'64 MB' if args.low_memory else '4 GB'}, "
              f"iterations={self.config.ARGON2_ITERATIONS}, parallelism={self.config.ARGON2_PARALLELISM}")
        print(f"Verbose: {args.verbose}, Debug: {args.debug}, Dry run: {args.dry_run}")

    def run(self) -> None:
        """Parse command-line arguments and execute the program."""
        parser = argparse.ArgumentParser(
            description=(
                f"{PROGRAM_NAME}: A secure file encryption/decryption tool using AES-256-GCM, HMAC-SHA512, and Argon2id.\n"
                f"Version {PROGRAM_VERSION}\n"
                "Encrypts or decrypts files with metadata stored in a 780-byte system block with a signature.\n"
                "Supports folder or single-file processing, analysis, and detailed logging.\n"
                "Password can be provided via --password, --password-file, or interactive prompt.\n"
                f"{COMPATIBILITY_WARNING}"
            ),
            epilog=(
                "Examples:\n"
                f"  Encrypt a folder: python crypt.argon2.py --encrypt --folder ./data --password mypass --verbose\n"
                f"  Decrypt a file: python crypt.argon2.py --decrypt --file ./encrypted/file --password-file ./pass.txt\n"
                f"  Analyze a file: python crypt.argon2.py --analyze --file ./encrypted/file --debug\n"
                f"  Dry run: python crypt.argon2.py --encrypt --folder ./data --password mypass --dry-run\n"
                f"  Low memory mode: python crypt.argon2.py --encrypt --folder ./data --password mypass --low-memory"
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument('--encrypt', action='store_true', help='Encrypt files in the specified folder or file')
        parser.add_argument('--decrypt', action='store_true', help='Decrypt files in the specified folder or file')
        parser.add_argument('--analyze', action='store_true', help='Analyze the system block of an encrypted file')
        parser.add_argument('--folder', type=str, help='Folder to process (required for encrypt/decrypt)')
        parser.add_argument('--file', type=str, help='Single file to process or analyze')
        parser.add_argument('--password', type=str, help='Password for encryption/decryption')
        parser.add_argument('--password-file', type=str, help='File containing the password (UTF-8)')
        parser.add_argument('--debug', action='store_true', help='Enable detailed debug output')
        parser.add_argument('--verbose', action='store_true', help='Enable verbose console output')
        parser.add_argument('--low-memory', action='store_true', help='Use lower memory settings for Argon2id (64 MB)')
        parser.add_argument('--dry-run', action='store_true', help='Simulate operations without writing files')
#       parser.add_argument('--force', action='store_true', help='Force operation, ignoring compatibility warnings')

        args = parser.parse_args()

        # Validate arguments
        if args.encrypt and args.decrypt:
            print(f"{Fore.RED}Error: Cannot specify both --encrypt and --decrypt{Style.RESET_ALL}")
            return
        if args.analyze and (args.encrypt or args.decrypt):
            print(f"{Fore.RED}Error: --analyze cannot be combined with --encrypt or --decrypt{Style.RESET_ALL}")
            return
        if args.analyze and not args.file:
            print(f"{Fore.RED}Error: --file is required for --analyze{Style.RESET_ALL}")
            return
        if (args.encrypt or args.decrypt) and not (args.folder or args.file):
            print(f"{Fore.RED}Error: Specify --folder or --file for --encrypt or --decrypt{Style.RESET_ALL}")
            return
        if args.folder and args.file:
            print(f"{Fore.RED}Error: Specify either --folder or --file, not both{Style.RESET_ALL}")
            return
        if args.folder:
            folder_path = Path(args.folder).expanduser()
            if not folder_path.exists():
                print(f"{Fore.RED}Error: Folder {folder_path} does not exist{Style.RESET_ALL}")
                return
            if not folder_path.is_dir():
                print(f"{Fore.RED}Error: {folder_path} is not a directory{Style.RESET_ALL}")
                return
        if args.file:
            file_path = Path(args.file).expanduser()
            if not file_path.exists():
                print(f"{Fore.RED}Error: File {file_path} does not exist{Style.RESET_ALL}")
                return
            if not file_path.is_file():
                print(f"{Fore.RED}Error: {file_path} is not a file{Style.RESET_ALL}")
                return
        if args.password and args.password_file:
            print(f"{Fore.RED}Error: Specify either --password or --password-file, not both{Style.RESET_ALL}")
            return

        self._print_startup_info(args)

        if args.analyze:
            processor = CryptFileProcessor(self.config, args.low_memory, args.verbose)
            processor.analyze_file(args.file, args.debug)
            return

        try:
            password = (
                args.password or
                (self._read_password_from_file(args.password_file) if args.password_file else None) or
                getpass.getpass(f"{Fore.CYAN}Enter password: {Style.RESET_ALL}")
            )
            self.logger.debug(f"Password provided (length: {len(password)} characters)")
        except Exception as e:
            self.logger.error(f"Failed to obtain password: {e}")
            print(f"{Fore.RED}Error obtaining password: {e}{Style.RESET_ALL}")
            return

        processor = CryptFileProcessor(self.config, args.low_memory, args.verbose)
        processor.process_folder(
            args.folder or Path(args.file).parent, password, 'encrypt' if args.encrypt else 'decrypt',
            Path(args.file).name if args.file else None, args.debug, args.dry_run
        )

if __name__ == "__main__":
    CryptCLI().run()
