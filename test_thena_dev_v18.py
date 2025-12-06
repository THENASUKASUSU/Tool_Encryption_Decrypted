import unittest
import os
import sys
import json
import shutil
from unittest.mock import patch, mock_open

# Add the path to the script to the system path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from Thena_dev_v18 import (
    config as global_config,
    encrypt_file_simple,
    decrypt_file_simple,
    encrypt_file_with_master_key,
    decrypt_file_with_master_key,
    load_or_create_master_key,
    main,
    load_config,
    secure_wipe_file
)

@patch('Thena_dev_v18.CONFIG_FILE', "thena_config_v18.json")
class TestThenaDev(unittest.TestCase):

    def setUp(self):
        """Set up test files and configuration."""
        self.test_dir = "test_data"
        os.makedirs(self.test_dir, exist_ok=True)
        self.input_file = os.path.join(self.test_dir, "test_input.txt")
        self.encrypted_file = os.path.join(self.test_dir, "test_input.txt.encrypted")
        self.decrypted_file = os.path.join(self.test_dir, "test_output.txt")
        self.master_key_file = ".master_key_encrypted_v18"
        self.config_file = "thena_config_v18.json"

        with open(self.input_file, "w") as f:
            f.write("This is a test file for Thena_dev_v18.")

        # Lower the Argon2 time cost to speed up tests
        config = load_config()
        config['argon2_time_cost'] = 1
        config['master_key_file'] = self.master_key_file
        config['custom_format_encrypt_header'] = False
        config['custom_format_shuffle'] = False
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=4)

        # Update the global config object in the imported module
        global_config.clear()
        global_config.update(config)

    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

        for file_path in [
            self.master_key_file,
            "test.keyfile",
            "wrong.keyfile",
            self.config_file
        ]:
            if os.path.exists(file_path):
                os.remove(file_path)

    def test_simple_encryption_decryption_success(self):
        """Test successful encryption and decryption in simple mode."""
        password = "test_password"
        # Since the functions now return a tuple (success, output_path)
        success_enc, _ = encrypt_file_simple(self.input_file, self.encrypted_file, password)
        self.assertTrue(success_enc, "Simple encryption failed.")
        self.assertTrue(os.path.exists(self.encrypted_file), "Encrypted file was not created.")

        success_dec, _ = decrypt_file_simple(self.encrypted_file, self.decrypted_file, password)
        self.assertTrue(success_dec, "Simple decryption failed.")
        self.assertTrue(os.path.exists(self.decrypted_file), "Decrypted file was not created.")

        with open(self.input_file, "r") as f_in, open(self.decrypted_file, "r") as f_out:
            self.assertEqual(f_in.read(), f_out.read(), "Decrypted content does not match original content.")

    def test_simple_decryption_wrong_password(self):
        """Test that simple decryption fails with the wrong password."""
        password = "test_password"
        wrong_password = "wrong_password"

        # Ensure that 'encrypt_file_simple' returns a tuple (bool, str)
        success_enc, _ = encrypt_file_simple(self.input_file, self.encrypted_file, password)
        self.assertTrue(success_enc, "Simple encryption failed during setup for wrong password test.")

        # Ensure that 'decrypt_file_simple' returns a tuple (bool, str)
        success_dec, _ = decrypt_file_simple(self.encrypted_file, self.decrypted_file, wrong_password)
        self.assertFalse(success_dec, "Simple decryption succeeded with the wrong password.")
        self.assertFalse(os.path.exists(self.decrypted_file), "Decrypted file was created with the wrong password.")

    def test_simple_encryption_decryption_with_keyfile(self):
        """Test successful encryption and decryption with a keyfile."""
        password = "test_password"
        keyfile_path = "test.keyfile"
        with open(keyfile_path, "w") as f:
            f.write("this is a keyfile")

        success_enc, _ = encrypt_file_simple(self.input_file, self.encrypted_file, password, keyfile_path=keyfile_path)
        self.assertTrue(success_enc, "Simple encryption with keyfile failed.")

        success_dec, _ = decrypt_file_simple(self.encrypted_file, self.decrypted_file, password, keyfile_path=keyfile_path)
        self.assertTrue(success_dec, "Simple decryption with keyfile failed.")

        with open(self.input_file, "r") as f_in, open(self.decrypted_file, "r") as f_out:
            self.assertEqual(f_in.read(), f_out.read(), "Decrypted content does not match original content with keyfile.")

    def test_simple_decryption_wrong_keyfile(self):
        """Test that simple decryption fails with the wrong keyfile."""
        password = "test_password"
        keyfile_path = "test.keyfile"
        wrong_keyfile_path = "wrong.keyfile"
        with open(keyfile_path, "w") as f:
            f.write("this is a keyfile")
        with open(wrong_keyfile_path, "w") as f:
            f.write("this is a wrong keyfile")

        success_enc, _ = encrypt_file_simple(self.input_file, self.encrypted_file, password, keyfile_path=keyfile_path)
        self.assertTrue(success_enc, "Simple encryption with keyfile failed during setup for wrong keyfile test.")

        success_dec, _ = decrypt_file_simple(self.encrypted_file, self.decrypted_file, password, keyfile_path=wrong_keyfile_path)
        self.assertFalse(success_dec, "Simple decryption succeeded with the wrong keyfile.")
        os.remove(wrong_keyfile_path) # Clean up the wrong keyfile

    def test_master_key_encryption_decryption_success(self):
        """Test successful encryption and decryption with a master key."""
        password = "test_password"
        master_key = load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key, "Master key creation failed.")

        success_enc, _ = encrypt_file_with_master_key(self.input_file, self.encrypted_file, master_key)
        self.assertTrue(success_enc, "Master key encryption failed.")

        success_dec, _ = decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)
        self.assertTrue(success_dec, "Master key decryption failed.")

        with open(self.input_file, "r") as f_in, open(self.decrypted_file, "r") as f_out:
            self.assertEqual(f_in.read(), f_out.read(), "Decrypted content does not match original content with master key.")

    def test_master_key_decryption_wrong_password(self):
        """Test that master key decryption fails with the wrong password."""
        password = "test_password"
        wrong_password = "wrong_password"

        # Create the first master key
        master_key = load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key, "Master key creation failed.")

        # Encrypt the file with the first master key
        success_enc, _ = encrypt_file_with_master_key(self.input_file, self.encrypted_file, master_key)
        self.assertTrue(success_enc, "Master key encryption failed.")

        # Remove the master key file to generate a new one
        if os.path.exists(self.master_key_file):
            os.remove(self.master_key_file)

        # Create a second, different master key
        wrong_master_key = load_or_create_master_key(wrong_password, None)
        self.assertIsNotNone(wrong_master_key, "Wrong master key creation failed.")

        # Ensure the keys are different
        self.assertNotEqual(master_key, wrong_master_key)

        # Decryption should fail with the wrong master key
        success_dec, _ = decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, wrong_master_key)
        self.assertFalse(success_dec, "Master key decryption succeeded with the wrong password.")

    @patch('Thena_dev_v18.encrypt_file_with_master_key')
    @patch('Thena_dev_v18.load_or_create_master_key')
    @patch('Thena_dev_v18.validate_password_keyfile', return_value=True)
    def test_main_encrypt_cli(self, mock_validate, mock_load_master_key, mock_encrypt):
        """Test the CLI for encryption."""
        mock_load_master_key.return_value = b'test_master_key'
        mock_encrypt.return_value = (True, self.encrypted_file)
        with patch('sys.argv', [
            'Thena_dev_v18.py',
            '--encrypt',
            '-i', self.input_file,
            '-o', self.encrypted_file,
            '-p', 'password'
        ]) as mock_args:
            # Since CRYPTOGRAPHY_AVAILABLE is True, it will use the master key path.
            main()
            mock_load_master_key.assert_called_with('password', None)
            mock_encrypt.assert_called_with(
                self.input_file,
                self.encrypted_file,
                b'test_master_key',
                add_random_padding=True,
                hide_paths=False
            )

    @patch('Thena_dev_v18.decrypt_file_with_master_key')
    @patch('Thena_dev_v18.load_or_create_master_key')
    @patch('Thena_dev_v18.validate_password_keyfile', return_value=True)
    def test_main_decrypt_cli(self, mock_validate, mock_load_master_key, mock_decrypt):
        """Test the CLI for decryption."""
        mock_load_master_key.return_value = b'test_master_key'
        mock_decrypt.return_value = (True, self.decrypted_file)

        # Create a dummy encrypted file for the test
        with open(self.encrypted_file, 'w') as f:
            f.write("dummy encrypted data")
        # Create a dummy master key file to prevent sys.exit(1) in main
        with open(self.master_key_file, 'w') as f:
            f.write("dummy master key data")

        with patch('sys.argv', [
            'Thena_dev_v18.py',
            '--decrypt',
            '-i', self.encrypted_file,
            '-o', self.decrypted_file,
            '-p', 'password'
        ]) as mock_args:
            main()
            mock_load_master_key.assert_called_with('password', None)
            mock_decrypt.assert_called_with(
                self.encrypted_file,
                self.decrypted_file,
                b'test_master_key',
                hide_paths=False
            )

    def test_encrypt_nonexistent_file(self):
        """Test that encrypting a non-existent file fails gracefully."""
        password = "test_password"
        non_existent_file = "non_existent_file.txt"
        success, _ = encrypt_file_simple(non_existent_file, self.encrypted_file, password)
        self.assertFalse(success, "Encryption succeeded for a non-existent file.")

    def test_decrypt_nonexistent_file(self):
        """Test that decrypting a non-existent file fails gracefully."""
        password = "test_password"
        non_existent_file = "non_existent_file.txt.encrypted"
        success, _ = decrypt_file_simple(non_existent_file, self.decrypted_file, password)
        self.assertFalse(success, "Decryption succeeded for a non-existent file.")

    def test_encrypt_empty_file(self):
        """Test that encrypting an empty file fails gracefully."""
        empty_file = os.path.join(self.test_dir, "empty_file.txt")
        with open(empty_file, "w") as f:
            pass  # create an empty file
        password = "test_password"
        success, _ = encrypt_file_simple(empty_file, self.encrypted_file, password)
        self.assertFalse(success, "Encryption succeeded for an empty file.")

    def test_decrypt_corrupted_file(self):
        """Test that decrypting a corrupted file fails."""
        password = "test_password"
        # 1. Encrypt the file
        success_enc, _ = encrypt_file_simple(self.input_file, self.encrypted_file, password)
        self.assertTrue(success_enc, "Encryption failed during setup for corrupted file test.")

        # 2. Corrupt the file by changing a byte in the ciphertext
        with open(self.encrypted_file, "r+b") as f:
            # Read the file to find the ciphertext part, assuming it's the last part
            # A more robust way would be to parse the file structure if it's complex
            data = f.read()
            # Simple corruption: flip a bit in the middle of the file
            middle_index = len(data) // 2
            corrupted_byte = data[middle_index:middle_index+1][0] ^ 0xff
            f.seek(middle_index)
            f.write(bytes([corrupted_byte]))

        # 3. Decryption should fail
        success_dec, _ = decrypt_file_simple(self.encrypted_file, self.decrypted_file, password)
        self.assertFalse(success_dec, "Decryption succeeded for a corrupted file.")

    def test_simple_encryption_with_header_encryption(self):
        """Test simple encryption with header encryption enabled."""
        # Enable header encryption for this test
        global_config['custom_format_encrypt_header'] = True

        password = "test_password_header"
        success_enc, _ = encrypt_file_simple(self.input_file, self.encrypted_file, password)
        self.assertTrue(success_enc, "Simple encryption with header encryption failed.")

        success_dec, _ = decrypt_file_simple(self.encrypted_file, self.decrypted_file, password)
        self.assertTrue(success_dec, "Simple decryption with header encryption failed.")

        with open(self.input_file, "r") as f_in, open(self.decrypted_file, "r") as f_out:
            self.assertEqual(f_in.read(), f_out.read(), "Decrypted content does not match original with header encryption.")

        # Reset the config
        global_config['custom_format_encrypt_header'] = False

    def test_master_key_encryption_with_header_encryption(self):
        """Test master key encryption with header encryption enabled."""
        # Enable header encryption for this test
        global_config['custom_format_encrypt_header'] = True

        password = "master_password_header"
        master_key = load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key, "Master key creation failed for header encryption test.")

        success_enc, _ = encrypt_file_with_master_key(self.input_file, self.encrypted_file, master_key)
        self.assertTrue(success_enc, "Master key encryption with header encryption failed.")

        success_dec, _ = decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)
        self.assertTrue(success_dec, "Master key decryption with header encryption failed.")

        with open(self.input_file, "r") as f_in, open(self.decrypted_file, "r") as f_out:
            self.assertEqual(f_in.read(), f_out.read(), "Decrypted content does not match original with master key and header encryption.")

        # Reset the config
        global_config['custom_format_encrypt_header'] = False

    def test_simple_header_encryption_mismatch_fail(self):
        """Test simple decryption fails when header encryption is expected but not present."""
        # Encrypt with header encryption
        global_config['custom_format_encrypt_header'] = True
        password = "test_password_mismatch"
        success_enc, _ = encrypt_file_simple(self.input_file, self.encrypted_file, password)
        self.assertTrue(success_enc, "Encryption with header encryption failed.")

        # Try to decrypt without header encryption
        global_config['custom_format_encrypt_header'] = False
        success_dec, _ = decrypt_file_simple(self.encrypted_file, self.decrypted_file, password)
        self.assertFalse(success_dec, "Decryption succeeded with a header encryption mismatch.")

    def test_master_key_header_encryption_mismatch_fail(self):
        """Test master key decryption fails when header encryption is expected but not present."""
        # Encrypt with header encryption
        global_config['custom_format_encrypt_header'] = True
        password = "master_password_mismatch"
        master_key = load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key, "Master key creation failed.")
        success_enc, _ = encrypt_file_with_master_key(self.input_file, self.encrypted_file, master_key)
        self.assertTrue(success_enc, "Master key encryption with header encryption failed.")

        # Try to decrypt without header encryption
        global_config['custom_format_encrypt_header'] = False
        success_dec, _ = decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)
        self.assertFalse(success_dec, "Master key decryption succeeded with a header encryption mismatch.")

    def test_simple_decryption_with_wrong_mode_marker(self):
        """Test that simple decryption fails if the file was encrypted with master key mode."""
        # 1. Encrypt with master key mode (marker 0x02)
        password = "master_password"
        master_key = load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key, "Master key creation failed.")
        success_enc, _ = encrypt_file_with_master_key(self.input_file, self.encrypted_file, master_key)
        self.assertTrue(success_enc, "Master key encryption failed.")

        # 2. Try to decrypt with simple mode (expects marker 0x01)
        simple_password = "simple_password"
        success_dec, _ = decrypt_file_simple(self.encrypted_file, self.decrypted_file, simple_password)
        self.assertFalse(success_dec, "Simple decryption succeeded on a master key encrypted file.")

    def test_master_key_decryption_with_wrong_mode_marker(self):
        """Test that master key decryption fails if the file was encrypted with simple mode."""
        # 1. Encrypt with simple mode (marker 0x01)
        password = "simple_password"
        success_enc, _ = encrypt_file_simple(self.input_file, self.encrypted_file, password)
        self.assertTrue(success_enc, "Simple encryption failed.")

        # 2. Try to decrypt with master key mode (expects marker 0x02)
        master_key_password = "master_password"
        master_key = load_or_create_master_key(master_key_password, None)
        self.assertIsNotNone(master_key, "Master key creation failed.")
        success_dec, _ = decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)
        self.assertFalse(success_dec, "Master key decryption succeeded on a simple encrypted file.")


class TestSecureWipeFile(unittest.TestCase):
    def setUp(self):
        """Set up a large test file."""
        self.test_file = "large_test_file.bin"
        self.file_size = 2 * 1024 * 1024  # 2MB
        with open(self.test_file, "wb") as f:
            f.write(os.urandom(self.file_size))

        # Load the configuration to be used in the test
        self.config = load_config()

    def tearDown(self):
        """Clean up the test file if it exists."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    @patch('builtins.print')
    def test_secure_wipe_large_file(self, mock_print):
        """Test that secure_wipe_file can handle a large file without MemoryError."""
        try:
            # Pass the loaded config to the function
            secure_wipe_file(self.test_file, passes=3)
        except MemoryError:
            self.fail("secure_wipe_file raised MemoryError with a large file.")

        # Check that the file is deleted
        self.assertFalse(os.path.exists(self.test_file), "The test file was not deleted after wiping.")


if __name__ == "__main__":
    unittest.main()
