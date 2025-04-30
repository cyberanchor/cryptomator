"""
Crypt - A cross-platform file encryption/decryption tool.

Overview:
- Encrypts files using AES-256-GCM, HMAC-SHA512, and PBKDF2.
- Stores metadata (filename, hash) in a fixed 692-byte system block.
- Supports decryption with integrity and authenticity checks.
- Provides analysis of encrypted file system blocks.
- Includes detailed logging and colored debug output.
- Handles Unicode filenames (up to 255 bytes in UTF-8).
- Enforces a minimum file size of 4 bytes.
- Supports password input via command-line, file, or interactive prompt.

Dependencies:
- Python 3.6+
- cryptography (pip install cryptography)
- colorama (pip install colorama)

Usage:
    python crypt.py --encrypt --folder ./path --password mypass
    python crypt.py --decrypt --folder ./path --password-file ./pass.txt
    python crypt.py --analyze --file ./path/file.enc
    python crypt.py --debug  # Enable debug output

System Block (692 bytes):
- Salt: 16 bytes (random, for PBKDF2 key derivation)
- Nonce: 12 bytes (random, for AES-256-GCM)
- HMAC: 64 bytes (SHA-512, signs data + padded_filename + hash)
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

Mini-RFC: Crypt File Encryption Protocol
- Version: 1.1
- Date: April 21, 2025
- Overview: Defines a secure method for file encryption/decryption.
- File Format: 692-byte system block + encrypted payload.
- Encryption: AES-256-GCM with PBKDF2-derived key, HMAC-SHA512 for integrity.
- Password: Supports command-line, file, or prompt; max recommended length 4096 characters.


"""
import os
import argparse
import getpass
import glob
import secrets
import hashlib
import struct
import logging
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag
from colorama import init, Fore, Style

# Initialize colorama for colored console output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    filename='crypt.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger()

# System block constants
SALT_LENGTH = 16  # Bytes for random salt (PBKDF2)
NONCE_LENGTH = 12  # Bytes for AES-256-GCM nonce
HMAC_LENGTH = 64  # Bytes for SHA-512 HMAC
FILENAME_LENGTH_FIELD = 4  # Bytes for encrypted filename length (always 496)
ENCRYPTED_FILENAME_LENGTH = 512  # Bytes for encrypted filename (496 + 16 GCM tag)
ENCRYPTED_HASH_LENGTH = 80  # Bytes for encrypted SHA-512 hash (64 + 16 GCM tag)
ORIGINAL_FILENAME_LENGTH_FIELD = 4  # Bytes for original filename length
SYSTEM_BLOCK_LENGTH = (
    SALT_LENGTH + NONCE_LENGTH + HMAC_LENGTH + FILENAME_LENGTH_FIELD +
    ENCRYPTED_FILENAME_LENGTH + ENCRYPTED_HASH_LENGTH + ORIGINAL_FILENAME_LENGTH_FIELD
)  # Total: 692 bytes
MIN_FILE_SIZE = 4  # Minimum input file size (bytes)
MAX_FILENAME_LENGTH = 255  # Maximum filename length (bytes, UTF-8)
MAX_PASSWORD_LENGTH = 4096  # Recommended maximum password length (characters)

def generate_random_filename(length=16):
    """Generate a random hex filename for encrypted files."""
    filename = secrets.token_hex(length // 2)
    logger.debug(f"Generated random filename: {filename}")
    return filename

def generate_salt():
    """Generate a random salt for PBKDF2."""
    salt = secrets.token_bytes(SALT_LENGTH)
    logger.debug(f"Generated salt: {salt.hex()}")
    return salt

def derive_key(password, salt):
    """Derive a 256-bit AES key using PBKDF2-HMAC-SHA512."""
    logger.debug(f"Deriving key with salt: {salt.hex()}")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,  # 256-bit key for AES
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode('utf-8'))
    logger.debug(f"Derived key: {key.hex()}")
    return key

def compute_file_hash(file_path):
    """Compute SHA-512 hash of a file."""
    logger.debug(f"Computing SHA-512 hash for: {file_path}")
    sha512 = hashlib.sha512()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha512.update(chunk)
    hash_value = sha512.digest()
    logger.debug(f"Computed SHA-512 hash: {hash_value.hex()}")
    return hash_value

def compute_hmac_sha512(data, key, salt):
    """Compute HMAC-SHA512 of data with salt."""
    logger.debug(f"Computing HMAC-SHA512 with salt: {salt.hex()}")
    h = hmac.HMAC(key, hashes.SHA512())
    h.update(salt + data)
    hmac_value = h.finalize()
    logger.debug(f"Computed HMAC-SHA512: {hmac_value.hex()}")
    return hmac_value

def read_password_from_file(file_path):
    """Read password from a file, stripping whitespace."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            password = f.read().strip()
        logger.debug(f"Read password from file: {file_path} (length: {len(password)} characters)")
        return password
    except Exception as e:
        logger.error(f"Failed to read password from {file_path}: {e}")
        raise ValueError(f"Error reading password file {file_path}: {e}")

def validate_password_length(password):
    """Check password length and warn if it exceeds the recommended maximum."""
    if len(password) > MAX_PASSWORD_LENGTH:
        warning = (
            f"Password length ({len(password)} characters) exceeds recommended maximum "
            f"({MAX_PASSWORD_LENGTH} characters). Processing will continue, but performance may be affected."
        )
        logger.warning(warning)
        print(f"{Fore.YELLOW}Warning: {warning}{Style.RESET_ALL}")

def encrypt_file(input_file, output_dir, password, debug=False):
    """Encrypt a file with AES-256-GCM and store metadata in a system block."""
    try:
        # Validate password length
        validate_password_length(password)

        # Validate file size
        file_size = os.path.getsize(input_file)
        if file_size < MIN_FILE_SIZE:
            raise ValueError(f"File {input_file} is too small (< {MIN_FILE_SIZE} bytes)")

        # Read file content and compute hash
        logger.debug(f"Reading file: {input_file}")
        with open(input_file, 'rb') as f:
            data = f.read()
        original_hash = compute_file_hash(input_file)

        # Get filename (UTF-8, up to 255 bytes)
        filename = os.path.basename(input_file).encode('utf-8')
        if len(filename) > MAX_FILENAME_LENGTH:
            raise ValueError(f"Filename {input_file} exceeds {MAX_FILENAME_LENGTH} bytes")
        original_filename_length = len(filename)
        logger.debug(f"Filename: {filename.decode('utf-8')}, length: {original_filename_length}")

        # Generate salt and derive key
        salt = generate_salt()
        key = derive_key(password, salt)

        # Encrypt content, filename, and hash
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(NONCE_LENGTH)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        # Pad filename to 496 bytes
        padded_filename = filename + b'\x00' * (496 - len(filename))
        encrypted_filename = aesgcm.encrypt(nonce, padded_filename, None)
        encrypted_hash = aesgcm.encrypt(nonce, original_hash, None)
        logger.debug(f"Nonce: {nonce.hex()}")
        logger.debug(f"Encrypted filename: {encrypted_filename.hex()[:64]}...")
        logger.debug(f"Encrypted hash: {encrypted_hash.hex()}")

        # Compute HMAC
        hmac_input = data + padded_filename + original_hash
        hmac_value = compute_hmac_sha512(hmac_input, key, salt)

        # Construct system block
        filename_length = len(padded_filename)  # Always 496
        system_block = (
            salt +
            nonce +
            hmac_value +
            struct.pack('>I', filename_length) +
            encrypted_filename +
            encrypted_hash +
            struct.pack('>I', original_filename_length)
        )
        if len(system_block) != SYSTEM_BLOCK_LENGTH:
            raise ValueError(f"System block length mismatch: {len(system_block)} bytes, expected {SYSTEM_BLOCK_LENGTH}")

        # Save encrypted file
        output_filename = generate_random_filename() + ".enc"
        output_path = os.path.join(output_dir, output_filename)
        with open(output_path, 'wb') as f:
            f.write(system_block + ciphertext)

        # Debug output
        if debug:
            print(f"{Fore.YELLOW}System block for {output_filename}:{Style.RESET_ALL}")
            print(f"  Offset 0: Salt ({SALT_LENGTH} bytes): {salt.hex()}")
            print(f"  Offset {SALT_LENGTH}: Nonce ({NONCE_LENGTH} bytes): {nonce.hex()}")
            print(f"  Offset {SALT_LENGTH + NONCE_LENGTH}: HMAC ({HMAC_LENGTH} bytes): {hmac_value.hex()}")
            print(f"  Offset {SALT_LENGTH + NONCE_LENGTH + HMAC_LENGTH}: Filename length ({FILENAME_LENGTH_FIELD} bytes): {filename_length}")
            print(f"  Offset {SALT_LENGTH + NONCE_LENGTH + HMAC_LENGTH + FILENAME_LENGTH_FIELD}: Filename ({ENCRYPTED_FILENAME_LENGTH} bytes): {encrypted_filename.hex()[:64]}...")
            print(f"  Offset {SALT_LENGTH + NONCE_LENGTH + HMAC_LENGTH + FILENAME_LENGTH_FIELD + ENCRYPTED_FILENAME_LENGTH}: Hash ({ENCRYPTED_HASH_LENGTH} bytes): {encrypted_hash.hex()}")
            print(f"  Offset {SALT_LENGTH + NONCE_LENGTH + HMAC_LENGTH + FILENAME_LENGTH_FIELD + ENCRYPTED_FILENAME_LENGTH + ENCRYPTED_HASH_LENGTH}: Original filename length ({ORIGINAL_FILENAME_LENGTH_FIELD} bytes): {original_filename_length}")

        logger.info(f"Encrypted {input_file} to {output_filename}")
        print(f"{Fore.GREEN}Encrypted {input_file} to {output_filename}{Style.RESET_ALL}")
    except Exception as e:
        logger.error(f"Encryption failed for {input_file}: {e}")
        print(f"{Fore.RED}Error encrypting {input_file}: {e}{Style.RESET_ALL}")
        raise

def decrypt_file(encrypted_file, output_dir, password, debug=False):
    """Decrypt a file and verify integrity using system block metadata."""
    temp_path = None
    try:
        # Validate password length
        validate_password_length(password)

        # Read encrypted file
        logger.debug(f"Reading encrypted file: {encrypted_file}")
        with open(encrypted_file, 'rb') as f:
            data = f.read()

        # Validate file size
        if len(data) < SYSTEM_BLOCK_LENGTH:
            raise ValueError(f"File {encrypted_file} too short ({len(data)} bytes, expected >= {SYSTEM_BLOCK_LENGTH})")

        # Parse system block
        offset = 0
        salt = data[offset:offset + SALT_LENGTH]
        offset += SALT_LENGTH
        nonce = data[offset:offset + NONCE_LENGTH]
        offset += NONCE_LENGTH
        stored_hmac = data[offset:offset + HMAC_LENGTH]
        offset += HMAC_LENGTH
        filename_length = struct.unpack('>I', data[offset:offset + FILENAME_LENGTH_FIELD])[0]
        offset += FILENAME_LENGTH_FIELD
        encrypted_filename = data[offset:offset + ENCRYPTED_FILENAME_LENGTH]
        offset += ENCRYPTED_FILENAME_LENGTH
        encrypted_hash = data[offset:offset + ENCRYPTED_HASH_LENGTH]
        offset += ENCRYPTED_HASH_LENGTH
        original_filename_length = struct.unpack('>I', data[offset:offset + ORIGINAL_FILENAME_LENGTH_FIELD])[0]
        offset += ORIGINAL_FILENAME_LENGTH_FIELD
        ciphertext = data[offset:]

        # Validate system block
        if filename_length != 496:
            raise ValueError(f"Invalid filename length: {filename_length}, expected 496")
        if len(encrypted_filename) != ENCRYPTED_FILENAME_LENGTH:
            raise ValueError(f"Invalid encrypted filename length: {len(encrypted_filename)}")
        if len(encrypted_hash) != ENCRYPTED_HASH_LENGTH:
            raise ValueError(f"Invalid encrypted hash length: {len(encrypted_hash)}")
        if not ciphertext:
            raise ValueError("No encrypted payload found")
        if original_filename_length > MAX_FILENAME_LENGTH:
            raise ValueError(f"Invalid original filename length: {original_filename_length}, expected <= {MAX_FILENAME_LENGTH}")

        logger.debug(f"System block for {encrypted_file}:")
        logger.debug(f"  Salt: {salt.hex()}")
        logger.debug(f"  Nonce: {nonce.hex()}")
        logger.debug(f"  HMAC: {stored_hmac.hex()}")
        logger.debug(f"  Filename length: {filename_length}")
        logger.debug(f"  Encrypted filename: {encrypted_filename.hex()[:64]}...")
        logger.debug(f"  Encrypted hash: {encrypted_hash.hex()}")
        logger.debug(f"  Original filename length: {original_filename_length}")

        # Debug output
        if debug:
            print(f"{Fore.YELLOW}System block for {encrypted_file}:{Style.RESET_ALL}")
            print(f"  Offset 0: Salt ({SALT_LENGTH} bytes): {salt.hex()}")
            print(f"  Offset {SALT_LENGTH}: Nonce ({NONCE_LENGTH} bytes): {nonce.hex()}")
            print(f"  Offset {SALT_LENGTH + NONCE_LENGTH}: HMAC ({HMAC_LENGTH} bytes): {stored_hmac.hex()}")
            print(f"  Offset {SALT_LENGTH + NONCE_LENGTH + HMAC_LENGTH}: Filename length ({FILENAME_LENGTH_FIELD} bytes): {filename_length}")
            print(f"  Offset {SALT_LENGTH + NONCE_LENGTH + HMAC_LENGTH + FILENAME_LENGTH_FIELD}: Filename ({ENCRYPTED_FILENAME_LENGTH} bytes): {encrypted_filename.hex()[:64]}...")
            print(f"  Offset {SALT_LENGTH + NONCE_LENGTH + HMAC_LENGTH + FILENAME_LENGTH_FIELD + ENCRYPTED_FILENAME_LENGTH}: Hash ({ENCRYPTED_HASH_LENGTH} bytes): {encrypted_hash.hex()}")
            print(f"  Offset {SALT_LENGTH + NONCE_LENGTH + HMAC_LENGTH + FILENAME_LENGTH_FIELD + ENCRYPTED_FILENAME_LENGTH + ENCRYPTED_HASH_LENGTH}: Original filename length ({ORIGINAL_FILENAME_LENGTH_FIELD} bytes): {original_filename_length}")

        # Derive key
        key = derive_key(password, salt)

        # Decrypt data
        aesgcm = AESGCM(key)
        try:
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            decrypted_padded_filename = aesgcm.decrypt(nonce, encrypted_filename, None)
            decrypted_hash = aesgcm.decrypt(nonce, encrypted_hash, None)
        except InvalidTag as e:
            logger.error(f"Decryption failed for {encrypted_file}: Invalid password or corrupted data")
            print(f"{Fore.RED}Decryption failed for {encrypted_file}: Invalid password or corrupted data{Style.RESET_ALL}")
            return

        # Recover filename
        decrypted_filename = decrypted_padded_filename[:original_filename_length]
        logger.debug(f"Decrypted filename: {decrypted_filename.decode('utf-8', errors='ignore')}")

        # Verify HMAC
        hmac_input = decrypted_data + decrypted_padded_filename + decrypted_hash
        computed_hmac = compute_hmac_sha512(hmac_input, key, salt)
        if computed_hmac != stored_hmac:
            logger.error(f"HMAC verification failed for {encrypted_file}")
            print(f"{Fore.RED}Error: HMAC verification failed for {encrypted_file}{Style.RESET_ALL}")
            return

        # Verify hash
        temp_path = os.path.join(output_dir, generate_random_filename() + ".tmp")
        with open(temp_path, 'wb') as f:
            f.write(decrypted_data)
        computed_hash = compute_file_hash(temp_path)
        if computed_hash != decrypted_hash:
            logger.error(f"Hash verification failed for {encrypted_file}")
            print(f"{Fore.RED}Error: Hash verification failed for {encrypted_file}{Style.RESET_ALL}")
            os.remove(temp_path)
            return

        # Save decrypted file
        output_filename = decrypted_filename.decode('utf-8', errors='replace')
        output_path = os.path.join(output_dir, output_filename)
        os.rename(temp_path, output_path)

        logger.info(f"Decrypted {encrypted_file} to {output_path}")
        print(f"{Fore.GREEN}Decrypted {encrypted_file} to {output_path}{Style.RESET_ALL}")
    except Exception as e:
        logger.error(f"Decryption failed for {encrypted_file}: {e}")
        print(f"{Fore.RED}Error decrypting {encrypted_file}: {e}{Style.RESET_ALL}")
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

def analyze_file(file_path, debug=False):
    """Analyze the system block of an encrypted file."""
    try:
        logger.debug(f"Analyzing file: {file_path}")
        with open(file_path, 'rb') as f:
            data = f.read()

        if len(data) < SYSTEM_BLOCK_LENGTH:
            raise ValueError(f"File {file_path} too short ({len(data)} bytes, expected >= {SYSTEM_BLOCK_LENGTH})")

        # Parse system block
        offset = 0
        salt = data[offset:offset + SALT_LENGTH]
        offset += SALT_LENGTH
        nonce = data[offset:offset + NONCE_LENGTH]
        offset += NONCE_LENGTH
        hmac_value = data[offset:offset + HMAC_LENGTH]
        offset += HMAC_LENGTH
        filename_length = struct.unpack('>I', data[offset:offset + FILENAME_LENGTH_FIELD])[0]
        offset += FILENAME_LENGTH_FIELD
        encrypted_filename = data[offset:offset + ENCRYPTED_FILENAME_LENGTH]
        offset += ENCRYPTED_FILENAME_LENGTH
        encrypted_hash = data[offset:offset + ENCRYPTED_HASH_LENGTH]
        offset += ENCRYPTED_HASH_LENGTH
        original_filename_length = struct.unpack('>I', data[offset:offset + ORIGINAL_FILENAME_LENGTH_FIELD])[0]
        payload_length = len(data) - SYSTEM_BLOCK_LENGTH

        # Output analysis
        print(f"{Fore.CYAN}Analysis of {file_path}:{Style.RESET_ALL}")
        print(f"File size: {len(data)} bytes")
        print(f"System block ({SYSTEM_BLOCK_LENGTH} bytes):")
        print(f"  Offset 0: Salt ({SALT_LENGTH} bytes): {salt.hex()}")
        print(f"  Offset {SALT_LENGTH}: Nonce ({NONCE_LENGTH} bytes): {nonce.hex()}")
        print(f"  Offset {SALT_LENGTH + NONCE_LENGTH}: HMAC ({HMAC_LENGTH} bytes): {hmac_value.hex()}")
        print(f"  Offset {SALT_LENGTH + NONCE_LENGTH + HMAC_LENGTH}: Filename length ({FILENAME_LENGTH_FIELD} bytes): {filename_length}")
        print(f"  Offset {SALT_LENGTH + NONCE_LENGTH + HMAC_LENGTH + FILENAME_LENGTH_FIELD}: Filename ({ENCRYPTED_FILENAME_LENGTH} bytes): {encrypted_filename.hex()[:64]}...")
        print(f"  Offset {SALT_LENGTH + NONCE_LENGTH + HMAC_LENGTH + FILENAME_LENGTH_FIELD + ENCRYPTED_FILENAME_LENGTH}: Hash ({ENCRYPTED_HASH_LENGTH} bytes): {encrypted_hash.hex()}")
        print(f"  Offset {SALT_LENGTH + NONCE_LENGTH + HMAC_LENGTH + FILENAME_LENGTH_FIELD + ENCRYPTED_FILENAME_LENGTH + ENCRYPTED_HASH_LENGTH}: Original filename length ({ORIGINAL_FILENAME_LENGTH_FIELD} bytes): {original_filename_length}")
        print(f"Encrypted payload: {payload_length} bytes")

        logger.info(
            f"Analyzed {file_path}: salt={salt.hex()}, nonce={nonce.hex()}, "
            f"filename_length={filename_length}, original_filename_length={original_filename_length}, "
            f"payload_size={payload_length}"
        )
    except Exception as e:
        logger.error(f"Analysis failed for {file_path}: {e}")
        print(f"{Fore.RED}Error analyzing {file_path}: {e}{Style.RESET_ALL}")

def process_folder(folder, password, mode='encrypt', single_file=None, debug=False):
    """Process files in a folder or a single file."""
    folder = os.path.expanduser(folder)
    output_dir = os.path.join(folder, 'encrypted' if mode == 'encrypt' else 'decrypted')
    os.makedirs(output_dir, exist_ok=True)
    logger.debug(f"Processing {mode} in folder: {folder}, output: {output_dir}")

    if single_file:
        file_path = os.path.join(folder, single_file)
        if not os.path.isfile(file_path):
            logger.error(f"File {file_path} does not exist")
            print(f"{Fore.RED}Error: File {file_path} does not exist{Style.RESET_ALL}")
            return
        if mode == 'encrypt':
            encrypt_file(file_path, output_dir, password, debug)
        elif mode == 'decrypt' and file_path.endswith('.enc'):
            decrypt_file(file_path, output_dir, password, debug)
        else:
            logger.warning(f"Skipping {file_path}: Not an encrypted file")
            print(f"{Fore.YELLOW}Skipping {file_path}: Not an encrypted file{Style.RESET_ALL}")
    else:
        if mode == 'encrypt':
            for file in glob.glob(os.path.join(folder, '*')):
                if os.path.isfile(file) and not file.endswith('.enc'):
                    encrypt_file(file, output_dir, password, debug)
        else:
            for enc_file in glob.glob(os.path.join(folder, '*.enc')):
                decrypt_file(enc_file, output_dir, password, debug)

def main():
    """Main function to parse arguments and execute commands."""
    parser = argparse.ArgumentParser(
        description=(
            "Crypt: A secure file encryption/decryption tool using AES-256-GCM, HMAC-SHA512, and PBKDF2.\n"
            "Encrypts or decrypts files with metadata stored in a 692-byte system block.\n"
            "Supports folder or single-file processing, analysis, and debug output.\n"
            "Password can be provided via --password, --password-file, or interactive prompt."
        ),
        epilog=(
            "Examples:\n"
            "  Encrypt a folder: python crypt.py --encrypt --folder ./data --password mypass\n"
            "  Decrypt a file: python crypt.py --decrypt --file ./encrypted/file.enc --password-file ./pass.txt\n"
            "  Analyze a file: python crypt.py --analyze --file ./encrypted/file.enc\n"
            "  Encrypt with max password: python crypt.py --encrypt --file ./test.txt --password-file ./max_password.txt\n"
            "  Enable debug: python crypt.py --encrypt --folder ./data --password mypass --debug"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--encrypt', action='store_true', help='Encrypt files in the specified folder or file')
    parser.add_argument('--decrypt', action='store_true', help='Decrypt .enc files in the specified folder or file')
    parser.add_argument('--analyze', action='store_true', help='Analyze the system block of an encrypted file')
    parser.add_argument('--folder', type=str, help='Folder to process (required for encrypt/decrypt)')
    parser.add_argument('--file', type=str, help='Single file to process or analyze')
    parser.add_argument('--password', type=str, help='Password for encryption/decryption')
    parser.add_argument('--password-file', type=str, help='File containing the password (UTF-8)')
    parser.add_argument('--debug', action='store_true', help='Enable detailed debug output')

    args = parser.parse_args()

    # Validate arguments
    if args.analyze:
        if not args.file:
            print(f"{Fore.RED}Error: --file is required for --analyze{Style.RESET_ALL}")
            return
        analyze_file(args.file, args.debug)
        return

    if not args.encrypt and not args.decrypt:
        print(f"{Fore.RED}Error: Specify --encrypt or --decrypt{Style.RESET_ALL}")
        return

    if not args.folder and not args.file:
        print(f"{Fore.RED}Error: Specify --folder or --file{Style.RESET_ALL}")
        return

    # Get password
    if args.password:
        password = args.password
        logger.debug(f"Password provided via --password (length: {len(password)} characters)")
    elif args.password_file:
        password = read_password_from_file(args.password_file)
    else:
        password = getpass.getpass(f"{Fore.CYAN}Enter password: {Style.RESET_ALL}")
        logger.debug(f"Password provided via prompt (length: {len(password)} characters)")

    mode = 'encrypt' if args.encrypt else 'decrypt'
    process_folder(args.folder or os.path.dirname(args.file), password, mode, args.file, args.debug)

if __name__ == "__main__":
    main()
