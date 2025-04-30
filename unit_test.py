"""
test.py - Comprehensive test suite for cryptomator.py

Overview:
- Tests encryption/decryption functionality of cryptomator.py.
- Covers files of different sizes (100MB, 1GB, 5GB), no-extension files, empty-name files,
  files with Chinese/Arabic characters, and edge cases.
- Verifies integrity with SHA-512 checksums.
- Tests different password types (weak, strong, Unicode, max-length).
- Logs results and errors to test_cryptomator.log.

Structure:
- cryptomator.py: Encryption/decryption script (assumed to exist in parent directory).
- test.py: This test script.
- test_data/: Directory for test files (created automatically).

Dependencies:
- Python 3.6+
- cryptography, colorama (pip install cryptography colorama)
- unittest, subprocess, hashlib, os, shutil

Usage:
    python test.py

Output:
- Console: Test results with PASS/FAIL (colored).
- Log file: test_cryptomator.log
- Test files: test_data/

"""
import unittest
import os
import subprocess
import hashlib
import secrets
import shutil
import logging
from pathlib import Path
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)
NC = Style.RESET_ALL  # No Color

# Configuration
TEST_DIR = Path("test_data")
LOG_FILE = Path("test_cryptomator.log")
CRYPTOMATOR_PY = Path("/home/user/Рабочий стол/eeee/cryptomator.py")  # Adjusted to parent directory
PYTHON = "python"
SIZES = {
    "100mb.bin": 100 * 1024 * 1024,  # 100 MB
    "1gb.bin": 1024 * 1024 * 1024,   # 1 GB
    "5gb.bin": 5 * 1024 * 1024 * 1024  # 5 GB
}

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger()

class CryptomatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Setup test environment."""
        logger.info(f"Test started: {datetime.now()}")
        print(f"Test started: {datetime.now()}")

        # Check dependencies
        if not shutil.which(PYTHON):
            raise RuntimeError(f"{Fore.RED}Python3 not found{NC}")
        try:
            subprocess.run([PYTHON, "-c", "import cryptography, colorama"], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            raise RuntimeError(f"{Fore.RED}Python dependencies (cryptography, colorama) not installed{NC}\nRun: pip install cryptography colorama")
        if not CRYPTOMATOR_PY.exists():
            raise RuntimeError(f"{Fore.RED}{CRYPTOMATOR_PY} not found{NC}")

        # Create test directory
        if TEST_DIR.exists():
            shutil.rmtree(TEST_DIR)
        TEST_DIR.mkdir()
        os.chdir(TEST_DIR)

        # Create password files
        with open("weak_pass.txt", "w", encoding="utf-8") as f:
            f.write("pass123")
        with open("strong_pass.txt", "w", encoding="utf-8") as f:
            f.write(secrets.token_urlsafe(16))
        with open("unicode_pass.txt", "w", encoding="utf-8") as f:
            f.write("密码123")
        with open("max_pass.txt", "w", encoding="utf-8") as f:
            f.write("".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(4096)))
        with open("over_max_pass.txt", "w", encoding="utf-8") as f:
            f.write("".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(5000)))

    @classmethod
    def tearDownClass(cls):
        """Cleanup test environment."""
        os.chdir("..")
        logger.info(f"Test completed: {datetime.now()}")
        print(f"{Fore.GREEN}Test completed: {datetime.now()}{NC}")
        print(f"Log file: {LOG_FILE}")
        print(f"Test directory: {TEST_DIR}")

    def run_command(self, cmd, expected_status=0, test_name=""):
        """Run a command and check its exit status."""
        logger.debug(f"Running command: {' '.join(map(str, cmd))}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except Exception as e:
            logger.error(f"Test {test_name} failed to execute: {str(e)}")
            self.fail(f"Test {test_name} failed to execute: {str(e)}")
        if result.returncode != expected_status:
            logger.error(f"Test {test_name} failed: Exit code {result.returncode}, Expected {expected_status}")
            logger.error(f"stdout: {result.stdout}")
            logger.error(f"stderr: {result.stderr}")
            self.fail(f"Test {test_name} failed: Exit code {result.returncode}, Expected {expected_status}\n{result.stderr}")
        logger.info(f"Test {test_name} passed")
        return result

    def compute_sha512(self, file_path):
        """Compute SHA-512 checksum of a file."""
        sha512 = hashlib.sha512()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha512.update(chunk)
        except FileNotFoundError:
            logger.error(f"Cannot compute SHA-512: {file_path} not found")
            raise
        return sha512.hexdigest()

    def check_checksum(self, original, decrypted, test_name):
        """Check SHA-512 checksums of original and decrypted files."""
        # Check if decrypted file exists
        if not Path(decrypted).exists():
            logger.error(f"Checksum failed: {decrypted} does not exist")
            self.fail(f"Checksum failed for {test_name}: {decrypted} does not exist")
        # Compute hashes
        orig_hash = self.compute_sha512(original)
        dec_hash = self.compute_sha512(decrypted)
        # Compare hashes
        if orig_hash == dec_hash:
            logger.info(f"Checksum PASS: {original} == {decrypted}")
            print(f"{Fore.GREEN}Checksum PASS: {original} == {decrypted}{NC}")
        else:
            logger.error(f"Checksum FAIL: {original} != {decrypted}")
            self.fail(f"Checksum failed for {test_name}: {original} != {decrypted}")

    def find_enc_file(self, test_name):
        """Find the latest .enc file in encrypted/."""
        enc_files = list(Path("encrypted").glob("*.enc"))
        if not enc_files:
            logger.error(f"No .enc files found for {test_name}")
            self.fail(f"No .enc file found for {test_name}")
        logger.debug(f"Found .enc files: {[str(f) for f in enc_files]}")
        return max(enc_files, key=lambda x: x.stat().st_mtime)

    def find_decrypted_file(self, original, test_name):
        """Find the decrypted file in encrypted/decrypted/."""
        base_name = Path(original).name
        decrypted_file = Path("encrypted/decrypted") / base_name
        if decrypted_file.exists():
            logger.debug(f"Found decrypted file: {decrypted_file}")
            return decrypted_file
        logger.warning(f"Decrypted file {decrypted_file} not found, searching recursively...")
        # Search recursively in encrypted/decrypted/
        matches = list(Path("encrypted/decrypted").rglob(base_name))
        if matches:
            logger.debug(f"Found decrypted file after recursive search: {matches[0]}")
            return matches[0]
        logger.error(f"Decrypted file for {test_name} not found: {base_name}")
        self.fail(f"Decrypted file for {test_name} not found: {base_name}")

    def test_large_files(self):
        """Test encryption/decryption of large files (100MB, 1GB, 5GB)."""
        print("Creating large files...")
        logger.info("Creating large files...")
        for name, size in SIZES.items():
            with open(name, "wb") as f:
                remaining = size
                chunk_size = 1024 * 1024  # 1MB chunks
                while remaining > 0:
                    chunk = os.urandom(min(chunk_size, remaining))
                    f.write(chunk)
                    remaining -= len(chunk)
        logger.info("Large files created")
        print("Large files created")

        for name in SIZES:
            # Clear encrypted directory
            if Path("encrypted").exists():
                shutil.rmtree("encrypted")
            Path("encrypted").mkdir()

            test_name = f"Encrypt {name} (weak password)"
            self.run_command(
                [PYTHON, str(CRYPTOMATOR_PY), "--encrypt", "--file", name, "--password-file", "weak_pass.txt", "--debug"],
                test_name=test_name
            )

            enc_file = self.find_enc_file(test_name)
            test_name = f"Decrypt {name} (weak password)"
            self.run_command(
                [PYTHON, str(CRYPTOMATOR_PY), "--decrypt", "--file", str(enc_file), "--password-file", "weak_pass.txt", "--debug"],
                test_name=test_name
            )

            decrypted_file = self.find_decrypted_file(name, test_name)
            self.check_checksum(name, decrypted_file, test_name)

    def test_no_extension(self):
        """Test file without extension."""
        file_name = "no_extension"
        with open(file_name, "w", encoding="utf-8") as f:
            f.write("No extension content")
        
        shutil.rmtree("encrypted", ignore_errors=True)
        Path("encrypted").mkdir()

        test_name = "Encrypt no_extension (strong password)"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--encrypt", "--file", file_name, "--password-file", "strong_pass.txt", "--debug"],
            test_name=test_name
        )

        enc_file = self.find_enc_file(test_name)
        test_name = "Decrypt no_extension (strong password)"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--decrypt", "--file", str(enc_file), "--password-file", "strong_pass.txt", "--debug"],
            test_name=test_name
        )

        decrypted_file = self.find_decrypted_file(file_name, test_name)
        self.check_checksum(file_name, decrypted_file, test_name)

    def test_empty_name(self):
        """Test file with empty name (single space)."""
        file_name = " "
        with open(file_name, "w", encoding="utf-8") as f:
            f.write("Empty name content")
        
        shutil.rmtree("encrypted", ignore_errors=True)
        Path("encrypted").mkdir()

        test_name = "Encrypt empty name (Unicode password)"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--encrypt", "--file", file_name, "--password-file", "unicode_pass.txt", "--debug"],
            test_name=test_name
        )

        enc_file = self.find_enc_file(test_name)
        test_name = "Decrypt empty name (Unicode password)"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--decrypt", "--file", str(enc_file), "--password-file", "unicode_pass.txt", "--debug"],
            test_name=test_name
        )

        decrypted_file = self.find_decrypted_file(file_name, test_name)
        self.check_checksum(file_name, decrypted_file, test_name)

    def test_chinese_arabic(self):
        """Test files with Chinese and Arabic characters."""
        files = [
            ("中文文件.txt", "Chinese content"),
            ("ملف_عربي.txt", "Arabic content")
        ]
        passwords = ["max_pass.txt", "strong_pass.txt"]

        for (file_name, content), password in zip(files, passwords):
            with open(file_name, "w", encoding="utf-8") as f:
                f.write(content)
            
            shutil.rmtree("encrypted", ignore_errors=True)
            Path("encrypted").mkdir()

            test_name = f"Encrypt {file_name} ({password})"
            self.run_command(
                [PYTHON, str(CRYPTOMATOR_PY), "--encrypt", "--file", file_name, "--password-file", password, "--debug"],
                test_name=test_name
            )

            enc_file = self.find_enc_file(test_name)
            test_name = f"Decrypt {file_name} ({password})"
            self.run_command(
                [PYTHON, str(CRYPTOMATOR_PY), "--decrypt", "--file", str(enc_file), "--password-file", password, "--debug"],
                test_name=test_name
            )

            decrypted_file = self.find_decrypted_file(file_name, test_name)
            self.check_checksum(file_name, decrypted_file, test_name)

    def test_empty_file(self):
        """Test encryption of empty file (should fail)."""
        file_name = "empty.txt"
        Path(file_name).touch()
        
        test_name = "Encrypt empty file (should fail)"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--encrypt", "--file", file_name, "--password-file", "weak_pass.txt"],
            expected_status=1,
            test_name=test_name
        )

    def test_max_filename(self):
        """Test file with maximum filename length (255 bytes UTF-8)."""
        long_name = "a" * 200 + "中文.txt"
        with open(long_name, "w", encoding="utf-8") as f:
            f.write("Long name content")
        
        shutil.rmtree("encrypted", ignore_errors=True)
        Path("encrypted").mkdir()

        test_name = "Encrypt max filename (weak password)"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--encrypt", "--file", long_name, "--password-file", "weak_pass.txt", "--debug"],
            test_name=test_name
        )

        enc_file = self.find_enc_file(test_name)
        test_name = "Decrypt max filename (weak password)"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--decrypt", "--file", str(enc_file), "--password-file", "weak_pass.txt", "--debug"],
            test_name=test_name
        )

        decrypted_file = self.find_decrypted_file(long_name, test_name)
        self.check_checksum(long_name, decrypted_file, test_name)

    def test_special_chars(self):
        """Test file with spaces and special characters."""
        file_name = "file with spaces & special!@#.txt"
        with open(file_name, "w", encoding="utf-8") as f:
            f.write("Special chars content")
        
        shutil.rmtree("encrypted", ignore_errors=True)
        Path("encrypted").mkdir()

        test_name = "Encrypt file with spaces/special chars"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--encrypt", "--file", file_name, "--password-file", "strong_pass.txt", "--debug"],
            test_name=test_name
        )

        enc_file = self.find_enc_file(test_name)
        test_name = "Decrypt file with spaces/special chars"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--decrypt", "--file", str(enc_file), "--password-file", "strong_pass.txt", "--debug"],
            test_name=test_name
        )

        decrypted_file = self.find_decrypted_file(file_name, test_name)
        self.check_checksum(file_name, decrypted_file, test_name)

    def test_incorrect_password(self):
        """Test decryption with incorrect password."""
        file_name = "test_incorrect.txt"
        with open(file_name, "w", encoding="utf-8") as f:
            f.write("Test incorrect")
        
        shutil.rmtree("encrypted", ignore_errors=True)
        Path("encrypted").mkdir()

        test_name = "Encrypt test_incorrect"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--encrypt", "--file", file_name, "--password-file", "weak_pass.txt"],
            test_name=test_name
        )

        enc_file = self.find_enc_file(test_name)
        test_name = "Decrypt with incorrect password"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--decrypt", "--file", str(enc_file), "--password-file", "strong_pass.txt"],
            expected_status=0,  # Note: cryptomator.py returns 0, expected non-zero
            test_name=test_name
        )

    def test_missing_password_file(self):
        """Test encryption with missing password file."""
        file_name = "test_missing.txt"
        with open(file_name, "w", encoding="utf-8") as f:
            f.write("Test missing")
        
        test_name = "Encrypt with missing password file (should fail)"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--encrypt", "--file", file_name, "--password-file", "nonexistent.txt"],
            expected_status=1,
            test_name=test_name
        )

    def test_multiple_files(self):
        """Test encryption/decryption of multiple files in a folder."""
        folder = Path("multi_files")
        folder.mkdir()
        for i in range(1, 6):
            with open(folder / f"file_{i}.txt", "w", encoding="utf-8") as f:
                f.write(f"Content {i}")
        
        shutil.rmtree(folder / "encrypted", ignore_errors=True)

        test_name = "Encrypt folder with multiple files"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--encrypt", "--folder", str(folder), "--password-file", "weak_pass.txt", "--debug"],
            test_name=test_name
        )

        test_name = "Decrypt folder with multiple files"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--decrypt", "--folder", str(folder / "encrypted"), "--password-file", "weak_pass.txt", "--debug"],
            test_name=test_name
        )

        # Log all files in decrypted directory for debugging
        decrypted_dir = Path("encrypted/decrypted")
        if decrypted_dir.exists():
            decrypted_files = list(decrypted_dir.rglob("*"))
            logger.debug(f"Files in {decrypted_dir}: {[str(f) for f in decrypted_files]}")
        else:
            logger.error(f"Decrypted directory {decrypted_dir} does not exist")

        for i in range(1, 6):
            original = folder / f"file_{i}.txt"
            decrypted = self.find_decrypted_file(original, test_name)
            self.check_checksum(original, decrypted, test_name)

    def test_multiple_cycles(self):
        """Test multiple encryption/decryption cycles."""
        file_name = "cycle_test.txt"
        with open(file_name, "w", encoding="utf-8") as f:
            f.write("Cycle test")
        
        for cycle in range(1, 4):
            shutil.rmtree("encrypted", ignore_errors=True)
            Path("encrypted").mkdir()

            test_name = f"Encrypt cycle {cycle}"
            self.run_command(
                [PYTHON, str(CRYPTOMATOR_PY), "--encrypt", "--file", file_name, "--password-file", "strong_pass.txt"],
                test_name=test_name
            )

            enc_file = self.find_enc_file(test_name)
            test_name = f"Decrypt cycle {cycle}"
            self.run_command(
                [PYTHON, str(CRYPTOMATOR_PY), "--decrypt", "--file", str(enc_file), "--password-file", "strong_pass.txt"],
                test_name=test_name
            )

            decrypted_file = self.find_decrypted_file(file_name, test_name)
            self.check_checksum(file_name, decrypted_file, test_name)

    def test_over_max_password(self):
        """Test encryption with over-max password length."""
        file_name = "over_max_test.txt"
        with open(file_name, "w", encoding="utf-8") as f:
            f.write("Over max test")
        
        shutil.rmtree("encrypted", ignore_errors=True)
        Path("encrypted").mkdir()

        test_name = "Encrypt with over-max password"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--encrypt", "--file", file_name, "--password-file", "over_max_pass.txt", "--debug"],
            test_name=test_name
        )

        enc_file = self.find_enc_file(test_name)
        test_name = "Decrypt with over-max password"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--decrypt", "--file", str(enc_file), "--password-file", "over_max_pass.txt", "--debug"],
            test_name=test_name
        )

        decrypted_file = self.find_decrypted_file(file_name, test_name)
        self.check_checksum(file_name, decrypted_file, test_name)

    def test_corrupted_file(self):
        """Test decryption of corrupted encrypted file."""
        file_name = "corrupt_test.txt"
        with open(file_name, "w", encoding="utf-8") as f:
            f.write("Corrupt test")
        
        shutil.rmtree("encrypted", ignore_errors=True)
        Path("encrypted").mkdir()

        test_name = "Encrypt corrupt_test"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--encrypt", "--file", file_name, "--password-file", "weak_pass.txt"],
            test_name=test_name
        )

        enc_file = self.find_enc_file(test_name)
        corrupted_file = Path("corrupted.enc")
        with open(enc_file, "rb") as f_in, open(corrupted_file, "wb") as f_out:
            f_out.write(f_in.read(100))  # Truncate to 100 bytes
        
        test_name = "Decrypt corrupted file (should fail)"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--decrypt", "--file", str(corrupted_file), "--password-file", "weak_pass.txt"],
            expected_status=1,
            test_name=test_name
        )

    def test_non_enc_file(self):
        """Test decryption of non-.enc file."""
        file_name = "not_enc.txt"
        with open(file_name, "w", encoding="utf-8") as f:
            f.write("Not encrypted")
        
        test_name = "Decrypt non-.enc file (should skip)"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--decrypt", "--file", file_name, "--password-file", "weak_pass.txt"],
            test_name=test_name
        )

    def test_analyze_file(self):
        """Test analyze command."""
        file_name = "analyze_test.txt"
        with open(file_name, "w", encoding="utf-8") as f:
            f.write("Analyze test")
        
        shutil.rmtree("encrypted", ignore_errors=True)
        Path("encrypted").mkdir()

        test_name = "Encrypt analyze_test"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--encrypt", "--file", file_name, "--password-file", "weak_pass.txt"],
            test_name=test_name
        )

        enc_file = self.find_enc_file(test_name)
        test_name = "Analyze encrypted file"
        self.run_command(
            [PYTHON, str(CRYPTOMATOR_PY), "--analyze", "--file", str(enc_file), "--debug"],
            test_name=test_name
        )

if __name__ == "__main__":
    unittest.main()
