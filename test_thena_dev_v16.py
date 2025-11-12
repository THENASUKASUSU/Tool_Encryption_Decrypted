import unittest
import os
import sys
from unittest import mock
import Thena_dev_v16 as Thena_dev

# Speed up tests by reducing the Argon2 time cost
Thena_dev.config["argon2_time_cost"] = 1

class TestThenaDevSimple(unittest.TestCase):
    """Tests for the simple encryption and decryption functionality."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file.txt"
        self.encrypted_file = "test_file.txt.encrypted"
        self.decrypted_file = "test_file.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for Thena_dev.py.")

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(Thena_dev.config["master_key_file"]):
            os.remove(Thena_dev.config["master_key_file"])

    def test_encrypt_decrypt_simple_aesgcm(self):
        """Test the simple encryption and decryption functionality with AES-GCM."""
        password = "Test_Password123!"
        Thena_dev.config["encryption_algorithm"] = "aes-gcm"
        Thena_dev.encrypt_file_simple(self.test_file, self.encrypted_file, password)
        Thena_dev.decrypt_file_simple(self.encrypted_file, self.decrypted_file, password)
        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

    def test_encrypt_decrypt_simple_chacha20(self):
        """Test the simple encryption and decryption functionality with ChaCha20-Poly1305."""
        password = "Test_Password123!"
        Thena_dev.config["encryption_algorithm"] = "chacha20-poly1305"
        Thena_dev.encrypt_file_simple(self.test_file, self.encrypted_file, password)
        Thena_dev.decrypt_file_simple(self.encrypted_file, self.decrypted_file, password)
        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

    def test_cli_missing_args(self):
        """Test the CLI with missing arguments."""
        import subprocess
        # Missing input file
        result = subprocess.run(["python3", "Thena_dev_v16.py", "--encrypt", "-o", self.encrypted_file, "-p", "pw"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        # Missing output file
        result = subprocess.run(["python3", "Thena_dev_v16.py", "--encrypt", "-i", self.test_file, "-p", "pw"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        # Missing password
        result = subprocess.run(["python3", "Thena_dev_v16.py", "--encrypt", "-i", self.test_file, "-o", self.encrypted_file], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)

    def test_encrypt_decrypt_simple_no_padding(self):
        """Test the simple encryption and decryption functionality without padding."""
        password = "Test_Password123!"
        Thena_dev.encrypt_file_simple(self.test_file, self.encrypted_file, password, add_random_padding=False)
        Thena_dev.decrypt_file_simple(self.encrypted_file, self.decrypted_file, password)
        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

    def test_encrypt_decrypt_master_key_no_padding(self):
        """Test the master key encryption and decryption functionality without padding."""
        password = "Test_Password123!"
        master_key = Thena_dev.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key)
        Thena_dev.encrypt_file_with_master_key(self.test_file, self.encrypted_file, master_key, add_random_padding=False)
        Thena_dev.decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)
        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

class TestThenaDevMasterKey(unittest.TestCase):
    """Tests for the master key encryption and decryption functionality."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file.txt"
        self.encrypted_file = "test_file.txt.encrypted"
        self.decrypted_file = "test_file.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for Thena_dev.py.")

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(Thena_dev.config["master_key_file"]):
            os.remove(Thena_dev.config["master_key_file"])

    def test_encrypt_decrypt_master_key_aesgcm(self):
        """Test the master key encryption and decryption functionality with AES-GCM."""
        password = "Test_Password123!"
        Thena_dev.config["encryption_algorithm"] = "aes-gcm"
        master_key = Thena_dev.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key)
        Thena_dev.encrypt_file_with_master_key(self.test_file, self.encrypted_file, master_key)
        Thena_dev.decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)
        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

    def test_encrypt_decrypt_master_key_chacha20(self):
        """Test the master key encryption and decryption functionality with ChaCha20-Poly1305."""
        password = "Test_Password123!"
        Thena_dev.config["encryption_algorithm"] = "chacha20-poly1305"
        master_key = Thena_dev.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key)
        Thena_dev.encrypt_file_with_master_key(self.test_file, self.encrypted_file, master_key)
        Thena_dev.decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)
        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)


class TestThenaDevCompression(unittest.TestCase):
    """Tests for the compression functionality."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file_compression.txt"
        self.encrypted_file = "test_file_compression.txt.encrypted"
        self.decrypted_file = "test_file_compression.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for compression." * 1000)

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(Thena_dev.config["master_key_file"]):
            os.remove(Thena_dev.config["master_key_file"])

    def test_compression_enabled(self):
        """Test encryption and decryption with compression enabled."""
        password = "Test_Password123!"
        original_compression = Thena_dev.config.get("enable_compression")
        Thena_dev.config["enable_compression"] = True

        master_key = Thena_dev.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key)

        Thena_dev.encrypt_file_with_master_key(self.test_file, self.encrypted_file, master_key)
        Thena_dev.decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)

        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

        # Restore the original compression setting
        Thena_dev.config["enable_compression"] = original_compression

class TestThenaDevScrypt(unittest.TestCase):
    """Tests for the Scrypt KDF functionality."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file_scrypt.txt"
        self.encrypted_file = "test_file_scrypt.txt.encrypted"
        self.decrypted_file = "test_file_scrypt.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for Scrypt.")

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(Thena_dev.config["master_key_file"]):
            os.remove(Thena_dev.config["master_key_file"])

    def test_scrypt_kdf(self):
        """Test encryption and decryption with the Scrypt KDF."""
        password = "Test_Password123!"
        original_kdf = Thena_dev.config.get("kdf_type")
        Thena_dev.config["kdf_type"] = "scrypt"

        master_key = Thena_dev.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key)

        Thena_dev.encrypt_file_with_master_key(self.test_file, self.encrypted_file, master_key)
        Thena_dev.decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)

        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

        # Restore the original KDF
        Thena_dev.config["kdf_type"] = original_kdf

class TestThenaDevPBKDF2(unittest.TestCase):
    """Tests for the PBKDF2 KDF functionality."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file_pbkdf2.txt"
        self.encrypted_file = "test_file_pbkdf2.txt.encrypted"
        self.decrypted_file = "test_file_pbkdf2.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for PBKDF2.")

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(Thena_dev.config["master_key_file"]):
            os.remove(Thena_dev.config["master_key_file"])

    def test_pbkdf2_kdf(self):
        """Test encryption and decryption with the PBKDF2 KDF."""
        password = "Test_Password123!"
        original_kdf = Thena_dev.config.get("kdf_type")
        Thena_dev.config["kdf_type"] = "pbkdf2"

        master_key = Thena_dev.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key)

        Thena_dev.encrypt_file_with_master_key(self.test_file, self.encrypted_file, master_key)
        Thena_dev.decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)

        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

        # Restore the original KDF
        Thena_dev.config["kdf_type"] = original_kdf

class TestThenaDevCLI(unittest.TestCase):
    """Tests for the command-line interface."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file.txt"
        self.encrypted_file = "test_file.txt.encrypted"
        self.decrypted_file = "test_file.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for Thena_dev.py CLI.")

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(Thena_dev.config["master_key_file"]):
            os.remove(Thena_dev.config["master_key_file"])

    def test_cli_encrypt_decrypt(self):
        """Test the command-line interface."""
        password = "Cli_Test_Password1!"
        # Test encryption
        encrypt_command = [
            "python3", "Thena_dev_v16.py",
            "--encrypt",
            "-i", self.test_file,
            "-o", self.encrypted_file,
            "-p", password
        ]
        import subprocess
        result = subprocess.run(encrypt_command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"Encryption failed with stderr: {result.stderr}")
        self.assertTrue(os.path.exists(self.encrypted_file))

        # Test decryption
        decrypt_command = [
            "python3", "Thena_dev_v16.py",
            "--decrypt",
            "-i", self.encrypted_file,
            "-o", self.decrypted_file,
            "-p", password
        ]
        result = subprocess.run(decrypt_command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"Decryption failed with stderr: {result.stderr}")
        self.assertTrue(os.path.exists(self.decrypted_file))

        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

class TestThenaDevErrorHandling(unittest.TestCase):
    """Tests for error handling."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file.txt"
        self.encrypted_file = "test_file.txt.encrypted"
        self.decrypted_file = "test_file.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for Thena_dev.py.")

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(Thena_dev.config["master_key_file"]):
            os.remove(Thena_dev.config["master_key_file"])

    def test_incorrect_password_simple(self):
        """Test decryption with an incorrect password."""
        password = "Correct_Password123!"
        incorrect_password = "Incorrect_Password123!"
        Thena_dev.encrypt_file_simple(self.test_file, self.encrypted_file, password)
        success, _ = Thena_dev.decrypt_file_simple(self.encrypted_file, self.decrypted_file, incorrect_password)
        self.assertFalse(success)
        self.assertFalse(os.path.exists(self.decrypted_file))

    def test_incorrect_password_master_key(self):
        """Test decryption with an incorrect password and master key."""
        password = "Correct_Password123!"
        incorrect_password = "Incorrect_Password123!"
        master_key = Thena_dev.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key)
        Thena_dev.encrypt_file_with_master_key(self.test_file, self.encrypted_file, master_key)
        # Attempt to load the master key with the incorrect password
        incorrect_master_key = Thena_dev.load_or_create_master_key(incorrect_password, None)
        self.assertIsNone(incorrect_master_key)

    def test_empty_file(self):
        """Test encryption and decryption of an empty file."""
        with open("empty_file.txt", "w") as f:
            pass
        password = "Test_Password123!"
        success, _ = Thena_dev.encrypt_file_simple("empty_file.txt", "empty_file.txt.encrypted", password)
        self.assertFalse(success)
        os.remove("empty_file.txt")

    def test_special_characters_in_filename(self):
        """Test encryption and decryption of a file with special characters in its name."""
        filename = "test_file_!@#$%^&*().txt"
        with open(filename, "w") as f:
            f.write("This is a test file with special characters in its name.")
        password = "Test_Password123!"
        encrypted_file = filename + ".encrypted"
        decrypted_file = filename + ".decrypted"
        Thena_dev.encrypt_file_simple(filename, encrypted_file, password)
        Thena_dev.decrypt_file_simple(encrypted_file, decrypted_file, password)
        with open(decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(filename, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)
        os.remove(filename)
        os.remove(encrypted_file)
        os.remove(decrypted_file)

    def test_validate_password_keyfile(self):
        """Test the password and keyfile validation function."""
        self.assertFalse(Thena_dev.validate_password_keyfile("short", None, interactive=False))
        self.assertFalse(Thena_dev.validate_password_keyfile("onlylowercase", None, interactive=False))
        self.assertFalse(Thena_dev.validate_password_keyfile("ONLYUPPERCASE", None, interactive=False))
        self.assertFalse(Thena_dev.validate_password_keyfile("123456789012", None, interactive=False))
        self.assertTrue(Thena_dev.validate_password_keyfile("Strong_Password123!", None, interactive=False))

    def test_confirm_overwrite(self):
        """Test the confirm overwrite function."""
        with open("test_overwrite.txt", "w") as f:
            f.write("test")
        # Simulate user input 'y'
        with mock.patch('builtins.input', return_value='y'):
            self.assertTrue(Thena_dev.confirm_overwrite("test_overwrite.txt"))
        # Simulate user input 'n'
        with mock.patch('builtins.input', return_value='n'):
            self.assertFalse(Thena_dev.confirm_overwrite("test_overwrite.txt"))
        os.remove("test_overwrite.txt")

    def test_check_file_size_limit(self):
        """Test the file size limit function."""
        with open("large_file.txt", "wb") as f:
            f.write(os.urandom(1024 * 1024)) # 1MB file
        Thena_dev.config["max_file_size"] = 1024 * 512 # 512KB limit
        self.assertFalse(Thena_dev.check_file_size_limit("large_file.txt"))
        Thena_dev.config["max_file_size"] = 1024 * 1024 * 2 # 2MB limit
        self.assertTrue(Thena_dev.check_file_size_limit("large_file.txt"))
        os.remove("large_file.txt")

    def test_clear_screen(self):
        """Test the clear screen function."""
        import platform
        import os
        # This is a bit tricky to test without actually clearing the screen.
        # We can just check that it doesn't raise an exception.
        try:
            Thena_dev.clear_screen()
        except Exception as e:
            self.fail(f"clear_screen() raised an exception: {e}")

class TestThenaDevHardening(unittest.TestCase):
    """Tests for the hardening features."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file_hardening.txt"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for hardening features.")

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def test_secure_wipe_file(self):
        """Test the secure file wiping functionality."""
        self.assertTrue(os.path.exists(self.test_file))
        Thena_dev.secure_wipe_file(self.test_file)
        self.assertFalse(os.path.exists(self.test_file))

class TestThenaDevMain(unittest.TestCase):
    """Tests for the main function."""

    def test_main_encrypt_decrypt(self):
        """Test the main function with encryption and decryption."""
        import subprocess
        # This test is interactive and requires user input.
        # We'll simulate user input by piping it to the process.
        password = "Main_Test_Password1!"
        test_file = "main_test_file.txt"
        with open(test_file, "w") as f:
            f.write("This is a test for the main function.")

        # Encrypt the file
        encrypt_input = f"1\n{test_file}\n{password}\nn\ny\nn\n"
        encrypt_process = subprocess.Popen(["python3", "Thena_dev_v16.py"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        encrypt_output, encrypt_error = encrypt_process.communicate(encrypt_input)

        # Find the encrypted file
        encrypted_file = None
        for file in os.listdir():
            if file.endswith(".encrypted"):
                encrypted_file = file
                break

        self.assertIsNotNone(encrypted_file, "Encrypted file not found.")

        # Decrypt the file
        decrypt_input = f"2\n{encrypted_file}\ndecrypted_{test_file}\n{password}\nn\ny\nn\n"
        decrypt_process = subprocess.Popen(["python3", "Thena_dev_v16.py"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        decrypt_output, decrypt_error = decrypt_process.communicate(decrypt_input)

        with open(f"decrypted_{test_file}", "r") as f:
            decrypted_content = f.read()

        with open(test_file, "r") as f:
            original_content = f.read()

        self.assertEqual(decrypted_content, original_content)

        # Clean up the files
        os.remove(test_file)
        os.remove(encrypted_file)
        os.remove(f"decrypted_{test_file}")


if __name__ == '__main__':
    unittest.main()
