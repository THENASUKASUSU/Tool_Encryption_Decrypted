import unittest
import os
import Thena_dev

class TestThenaDevSimple(unittest.TestCase):
    """Test case for simple encryption and decryption."""

    def setUp(self):
        """Set up the test environment."""
        self.test_file = "test_file.txt"
        self.encrypted_file = "test_file.txt.encrypted"
        self.decrypted_file = "test_file.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for Thena_dev.py.")

    def tearDown(self):
        """Clean up the test environment."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(".master_key_encrypted_v15"):
            os.remove(".master_key_encrypted_v15")

    def test_encrypt_decrypt_simple(self):
        """Test simple encryption and decryption of a file."""
        password = "Test_Password123!"
        Thena_dev.encrypt_file_simple(self.test_file, self.encrypted_file, password)
        Thena_dev.decrypt_file_simple(self.encrypted_file, self.decrypted_file, password)
        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

class TestThenaDevMasterKey(unittest.TestCase):
    """Test case for master key encryption and decryption."""

    def setUp(self):
        """Set up the test environment."""
        self.test_file = "test_file.txt"
        self.encrypted_file = "test_file.txt.encrypted"
        self.decrypted_file = "test_file.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for Thena_dev.py.")

    def tearDown(self):
        """Clean up the test environment."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(".master_key_encrypted_v15"):
            os.remove(".master_key_encrypted_v15")

    def test_encrypt_decrypt_master_key(self):
        """Test master key encryption and decryption of a file."""
        password = "Test_Password123!"
        master_key = Thena_dev.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key)
        Thena_dev.encrypt_file_with_master_key(self.test_file, self.encrypted_file, master_key)
        Thena_dev.decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)
        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

class TestThenaDevCLI(unittest.TestCase):
    """Test case for the command-line interface."""

    def setUp(self):
        """Set up the test environment."""
        self.test_file = "test_file.txt"
        self.encrypted_file = "test_file.txt.encrypted"
        self.decrypted_file = "test_file.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for Thena_dev.py CLI.")

    def tearDown(self):
        """Clean up the test environment."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(".master_key_encrypted_v15"):
            os.remove(".master_key_encrypted_v15")

    def test_cli_encrypt_decrypt(self):
        """Test encryption and decryption using the CLI."""
        password = "Cli_Test_Password1!"
        # Test encryption
        encrypt_command = [
            "python3", "Thena_dev.py",
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
            "python3", "Thena_dev.py",
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

class TestThenaDevBcrypt(unittest.TestCase):
    """Test case for bcrypt KDF."""

    def setUp(self):
        """Set up the test environment."""
        self.test_file = "test_file.txt"
        self.encrypted_file = "test_file.txt.encrypted"
        self.decrypted_file = "test_file.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for Thena_dev.py.")

        # Configure Thena_dev to use bcrypt
        Thena_dev.config['kdf_type'] = 'bcrypt'

    def tearDown(self):
        """Clean up the test environment."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(".master_key_encrypted_v15"):
            os.remove(".master_key_encrypted_v15")

    def test_encrypt_decrypt_bcrypt(self):
        """Test encryption and decryption of a file using bcrypt KDF."""
        password = "Test_Password123!"
        Thena_dev.encrypt_file_simple(self.test_file, self.encrypted_file, password)
        Thena_dev.decrypt_file_simple(self.encrypted_file, self.decrypted_file, password)
        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

if __name__ == '__main__':
    unittest.main()
