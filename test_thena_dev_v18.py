import unittest
import os
import sys
import json
import shutil
from unittest.mock import patch, mock_open

# Add the path to the script to the system path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the module to be tested
import Thena_dev_v18 as thena

class TestThenaDev(unittest.TestCase):
    """Test suite for the Thena_dev_v18 encryption script."""

    def setUp(self):
        """Set up the test environment before each test.

        This method creates a test directory, a sample input file, and patches
        the script's configuration to use test-specific values.
        """
        self.test_dir = "test_data"
        os.makedirs(self.test_dir, exist_ok=True)
        self.input_file = os.path.join(self.test_dir, "test_input.txt")
        self.encrypted_file = os.path.join(self.test_dir, "test_input.txt.encrypted")
        self.decrypted_file = os.path.join(self.test_dir, "test_output.txt")
        self.master_key_file = ".master_key_encrypted_v18"

        with open(self.input_file, "w") as f:
            f.write("This is a test file for Thena_dev_v18.")

        # Create a test-specific config
        test_config = {
            "argon2_time_cost": 1,
            "master_key_file": self.master_key_file,
        }

        # Patch the config object in the module where it's used
        self.config_patcher = patch.dict(thena.config, test_config)
        self.config_patcher.start()

    def tearDown(self):
        """Clean up the test environment after each test.

        This method stops the config patcher and removes the test directory
        and any created files to ensure a clean state for subsequent tests.
        """
        self.config_patcher.stop()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

        for file_path in [self.master_key_file, "test.keyfile", "wrong.keyfile", "thena_config_v18.json"]:
            if os.path.exists(file_path):
                os.remove(file_path)

    @patch('builtins.input', return_value='y')
    @patch('Thena_dev_v18.print_box')
    @patch('Thena_dev_v18.print_error_box')
    @patch('Thena_dev_v18.print_loading_progress')
    def test_simple_encryption_decryption_success(self, mock_loading, mock_error, mock_box, mock_input):
        """Test successful encryption and decryption in simple mode.

        This test verifies that a file can be encrypted and then decrypted
        successfully, and that the decrypted content matches the original.
        """
        password = "test_password"
        success_enc, _ = thena.encrypt_file_simple(self.input_file, self.encrypted_file, password)
        self.assertTrue(success_enc, "Simple encryption failed.")
        self.assertTrue(os.path.exists(self.encrypted_file), "Encrypted file was not created.")

        success_dec, _ = thena.decrypt_file_simple(self.encrypted_file, self.decrypted_file, password)
        self.assertTrue(success_dec, "Simple decryption failed.")
        self.assertTrue(os.path.exists(self.decrypted_file), "Decrypted file was not created.")

        with open(self.input_file, "r") as f_in, open(self.decrypted_file, "r") as f_out:
            self.assertEqual(f_in.read(), f_out.read(), "Decrypted content does not match original content.")

    @patch('builtins.input', return_value='y')
    @patch('Thena_dev_v18.print_box')
    @patch('Thena_dev_v18.print_error_box')
    @patch('Thena_dev_v18.print_loading_progress')
    def test_simple_decryption_wrong_password(self, mock_loading, mock_error, mock_box, mock_input):
        """Test that simple decryption fails with the wrong password.

        This test ensures that the script correctly handles incorrect passwords
        and does not decrypt the file or create an output file.
        """
        password = "test_password"
        wrong_password = "wrong_password"

        success_enc, _ = thena.encrypt_file_simple(self.input_file, self.encrypted_file, password)
        self.assertTrue(success_enc, "Simple encryption failed during setup for wrong password test.")

        success_dec, _ = thena.decrypt_file_simple(self.encrypted_file, self.decrypted_file, wrong_password)
        self.assertFalse(success_dec, "Simple decryption succeeded with the wrong password.")
        self.assertFalse(os.path.exists(self.decrypted_file), "Decrypted file was created with the wrong password.")

    @patch('builtins.input', return_value='y')
    @patch('Thena_dev_v18.print_box')
    @patch('Thena_dev_v18.print_error_box')
    @patch('Thena_dev_v18.print_loading_progress')
    def test_master_key_encryption_decryption_success(self, mock_loading, mock_error, mock_box, mock_input):
        """Test successful encryption and decryption with a master key.

        This test verifies the master key functionality, ensuring that a file
        can be encrypted and decrypted correctly using the master key system.
        """
        password = "test_password"
        master_key = thena.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key, "Master key creation failed.")

        success_enc, _ = thena.encrypt_file_with_master_key(self.input_file, self.encrypted_file, master_key)
        self.assertTrue(success_enc, "Master key encryption failed.")

        success_dec, _ = thena.decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)
        self.assertTrue(success_dec, "Master key decryption failed.")

        with open(self.input_file, "r") as f_in, open(self.decrypted_file, "r") as f_out:
            self.assertEqual(f_in.read(), f_out.read(), "Decrypted content does not match original content with master key.")

    @patch('builtins.input', return_value='y')
    @patch('Thena_dev_v18.print_box')
    @patch('Thena_dev_v18.print_error_box')
    @patch('Thena_dev_v18.print_loading_progress')
    def test_master_key_decryption_wrong_password(self, mock_loading, mock_error, mock_box, mock_input):
        """Test that master key decryption fails with the wrong password.

        This test ensures that the master key cannot be loaded with an
        incorrect password, preventing unauthorized decryption.
        """
        password = "test_password"
        wrong_password = "wrong_password"

        master_key = thena.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key, "Master key creation failed.")

        success_enc, _ = thena.encrypt_file_with_master_key(self.input_file, self.encrypted_file, master_key)
        self.assertTrue(success_enc, "Master key encryption failed.")

        wrong_master_key = thena.load_or_create_master_key(wrong_password, None)
        self.assertIsNone(wrong_master_key, "Master key creation should fail with wrong password.")

    @patch('sys.exit')
    @patch('builtins.input', return_value='y')
    @patch('Thena_dev_v18.print_box')
    @patch('Thena_dev_v18.print_error_box')
    @patch('Thena_dev_v18.encrypt_file_with_master_key')
    @patch('Thena_dev_v18.load_or_create_master_key')
    def test_main_encrypt_cli(self, mock_load_master_key, mock_encrypt, mock_error, mock_box, mock_input, mock_exit):
        """Test the command-line interface for encryption.

        This test simulates running the script from the command line to perform
        encryption and verifies that the correct functions are called.
        """
        mock_load_master_key.return_value = b'test_master_key'
        mock_encrypt.return_value = (True, self.encrypted_file)
        with patch('sys.argv', ['Thena_dev_v18.py', '--encrypt', '-i', self.input_file, '-o', self.encrypted_file, '-p', 'password']):
            thena.main()
            mock_load_master_key.assert_called_with('password', None, hide_paths=False)
            mock_encrypt.assert_called_with(self.input_file, self.encrypted_file, b'test_master_key', add_random_padding=True, hide_paths=False)

    @patch('sys.exit')
    @patch('builtins.input', return_value='y')
    @patch('Thena_dev_v18.print_box')
    @patch('Thena_dev_v18.print_error_box')
    @patch('Thena_dev_v18.decrypt_file_with_master_key')
    @patch('Thena_dev_v18.load_or_create_master_key')
    def test_main_decrypt_cli(self, mock_load_master_key, mock_decrypt, mock_error, mock_box, mock_input, mock_exit):
        """Test the command-line interface for decryption.

        This test simulates running the script from the command line to perform
        decryption and verifies that the correct functions are called.
        """
        mock_load_master_key.return_value = b'test_master_key'
        mock_decrypt.return_value = (True, self.decrypted_file)

        with open(self.encrypted_file, 'w') as f: f.write("dummy encrypted data")
        with open(self.master_key_file, 'w') as f: f.write("dummy master key data")

        with patch('sys.argv', ['Thena_dev_v18.py', '--decrypt', '-i', self.encrypted_file, '-o', self.decrypted_file, '-p', 'password']):
            thena.main()
            mock_load_master_key.assert_called_with('password', None, hide_paths=False)
            mock_decrypt.assert_called_with(self.encrypted_file, self.decrypted_file, b'test_master_key', hide_paths=False)

    @patch('builtins.input', return_value='y')
    @patch('Thena_dev_v18.print_box')
    @patch('Thena_dev_v18.print_error_box')
    @patch('Thena_dev_v18.print_loading_progress')
    def test_decoy_blocks_feature(self, mock_loading, mock_error, mock_box, mock_input):
        """Test that decoy blocks are added and ignored correctly.

        This test verifies that when the decoy blocks feature is enabled, the
        encrypted file size increases, but the decrypted content remains
        unaffected and correct.
        """
        password = "test_password"
        # Enable decoy blocks in config
        thena.config['enable_decoy_blocks'] = True
        thena.config['decoy_block_count'] = 3
        thena.config['decoy_block_max_size'] = 128

        original_size = os.path.getsize(self.input_file)

        success_enc, _ = thena.encrypt_file_simple(self.input_file, self.encrypted_file, password)
        self.assertTrue(success_enc, "Encryption with decoy blocks failed.")

        # Check that the encrypted file is larger than the original
        encrypted_size = os.path.getsize(self.encrypted_file)
        self.assertTrue(encrypted_size > original_size, "Encrypted file with decoys is not larger.")

        success_dec, _ = thena.decrypt_file_simple(self.encrypted_file, self.decrypted_file, password)
        self.assertTrue(success_dec, "Decryption with decoy blocks failed.")

        with open(self.input_file, "r") as f_in, open(self.decrypted_file, "r") as f_out:
            self.assertEqual(f_in.read(), f_out.read(), "Decrypted content does not match original after decoy blocks.")

if __name__ == "__main__":
    unittest.main()
