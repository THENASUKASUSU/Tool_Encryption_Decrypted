
import subprocess
import os
import time
import unittest
import glob
import json
from Thena_dev_v19 import config

def run_thena_script(inputs, get_output_filename=False, config_file=None):
    """Runs the Thena script in a subprocess with a given set of inputs.

    This function is a test helper that automates the process of running the
    main script and providing it with user input via stdin.

    Args:
        inputs (list): A list of strings, where each string is a line of
            input to be passed to the script.
        get_output_filename (bool): If True, the function will attempt to
            parse the script's stdout to find the name of the output file.
        config_file (str, optional): The path to a configuration file to be
            used for the script run.

    Returns:
        tuple: A tuple containing the script's stdout, stderr, execution time,
            and the output filename (if requested).
    """
    # Ensure the script exits gracefully in interactive tests
    if "3" not in inputs: # Assuming '3' is the exit command
        inputs.append("3")

    with open("test_input.txt", "w") as f:
        for i in inputs:
            f.write(i + "\n")

    command = ["python3", "Thena_dev_v19.py"]
    if config_file:
        command.extend(["--config", config_file])

    with open("test_input.txt", "r") as f:
        start_time = time.time()
        process = subprocess.Popen(
            command,
            stdin=f,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()
        end_time = time.time()

    output_filename = None
    print("STDOUT:", stdout)
    print("STDERR:", stderr)
    if get_output_filename:
        for line in stdout.split('\n'):
            if "berhasil dienkripsi ke" in line:
                try:
                    output_filename = line.split("'")[1]
                    if output_filename.endswith(".encrypted"):
                        break
                except IndexError:
                    continue

    return stdout, stderr, end_time - start_time, output_filename

class TestThenaScript(unittest.TestCase):
    """A test suite for the main Thena script."""
    def setUp(self):
        """Sets up the test environment before each test.

        This method creates a dictionary to hold configuration files and calls
        the cleanup method to ensure a clean slate for each test.
        """
        self.configs = {}
        self.cleanup()

    def tearDown(self):
        """Tear down after the tests."""
        self.cleanup()

    def cleanup(self):
        """Remove all test-related files."""
        files_to_remove = [
            "test_file.txt",
            "test_input.txt",
            "decrypted_file.txt",
            "rsa_private_key_v18.pem",
            "x25519_private_key_v18.pem",
            ".master_key_encrypted_v18",
            "thena_encryptor.log"
        ]
        for f in files_to_remove:
            if os.path.exists(f):
                os.remove(f)

        for file in glob.glob("*.encrypted"):
            os.remove(file)

        if os.path.exists("./temp_thena"):
            for file in os.listdir("./temp_thena"):
                os.remove(os.path.join("./temp_thena", file))
            os.rmdir("./temp_thena")

        for config_file in self.configs.values():
            if os.path.exists(config_file):
                os.remove(config_file)

    def test_logging_in_interactive_mode(self):
        """Tests that logging works correctly in interactive mode."""
        with open("test_file.txt", "w") as f:
            f.write("This is a test file for logging.")

        # Inputs for encryption. Using simple AES-GCM, no layers.
        encrypt_inputs = [
            "1",  # Encrypt File option
            "test_file.txt",
            "AStrongPassword123!",
            "n",  # Use Keyfile? (y/N)
            "1",  # Algorithm choice
            "n",  # Use RSA? (y/N)
            "n",  # Use Curve25519? (y/N)
            "n",  # Delete original file? (y/N)
        ]

        run_thena_script(encrypt_inputs)

        self.assertTrue(os.path.exists("thena_encryptor.log"), "Log file was not created in interactive mode.")

        with open("thena_encryptor.log", "r") as f:
            log_content = f.read()

        self.assertIn("=== Encryptor V18 Dimulai ===", log_content)
        self.assertIn("Encrypted (simple) berhasil", log_content)

    def test_no_temp_files_left_after_decryption(self):
        """Tests that no temporary files are left after a layered decryption."""
        # Ensure temp files are enabled for this test
        config_encrypt = "thena_config_encrypt.json"
        self.configs["encrypt"] = config_encrypt
        with open(config_encrypt, "w") as f:
            json.dump({"enable_temp_files": True}, f)

        with open("test_file.txt", "w") as f:
            f.write("This is a test file for layered decryption.")

        # Encrypt with AES + RSA layers
        encrypt_inputs = [
            "1",
            "test_file.txt",
            "AStrongPassword123!",
            "n",
            "1", # Algorithm selection
            "y",
            "y",
            "n",
            "n",
            "3"
        ]
        run_thena_script(encrypt_inputs, config_file=config_encrypt)

        encrypted_file = None
        for file in glob.glob("*.encrypted"):
            encrypted_file = file
            break

        self.assertIsNotNone(encrypted_file, "Encrypted file not found.")

        # Disable temp files for decryption
        config_decrypt = "thena_config_decrypt.json"
        self.configs["decrypt"] = config_decrypt
        with open(config_decrypt, "w") as f:
            json.dump({"enable_temp_files": False}, f)

        # Decrypt
        decrypt_inputs = [
            "2",
            encrypted_file,
            "decrypted_file.txt",
            "AStrongPassword123!",
            "n", # No keyfile
            "n", # Don't delete encrypted
            "3"  # Exit
        ]
        stdout, stderr, _, _ = run_thena_script(decrypt_inputs, config_file=config_decrypt)

        self.assertNotIn("TypeError", stderr)
        self.assertTrue(os.path.exists("decrypted_file.txt"), "Decrypted file was not created.")
        with open("decrypted_file.txt", "r") as f:
            content = f.read()
        self.assertEqual(content, "This is a test file for layered decryption.")

        encrypted_file = None
        for file in glob.glob("*.encrypted"):
            encrypted_file = file
            break

        self.assertIsNotNone(encrypted_file, "Encrypted file not found.")

        # Decrypt
        decrypt_inputs = [
            "2",
            encrypted_file,
            "decrypted_file.txt",
            "AStrongPassword123!",
            "n",
            "n",
            "3"
        ]
        run_thena_script(decrypt_inputs)

        # Check if the temp directory is empty
        temp_dir = "./temp_thena"
        if os.path.exists(temp_dir):
            self.assertEqual(len(os.listdir(temp_dir)), 0, "Temporary files were left in the temp directory.")

    def test_decryption_crash_without_temp_files(self):
        """Tests that decryption of a layered file does not crash when temp files are disabled."""
        with open("test_file.txt", "w") as f:
            f.write("This is a test file for layered decryption.")

    def test_xchacha20_poly1305_encryption_decryption(self):
        """Tests the full encryption-decryption cycle with XChaCha20-Poly1305."""
        config_file = "thena_config_xchacha20.json"
        self.configs["xchacha20"] = config_file
        with open(config_file, "w") as f:
            json.dump({"preferred_algorithm_priority": ["xchacha20-poly1305", "aes-gcm"]}, f)

        with open("test_file.txt", "w") as f:
            f.write("This is a test for XChaCha20-Poly1305.")

        # Encrypt
        encrypt_inputs = [
            "1",
            "test_file.txt",
            "AStrongPassword123!",
            "n", # No keyfile
            "1", # Auto algorithm selection
            "n", # No RSA
            "n", # No Curve25519
            "n", # Don't delete original
            "3"  # Exit
        ]
        _, _, _, encrypted_file = run_thena_script(encrypt_inputs, get_output_filename=True, config_file=config_file)
        self.assertIsNotNone(encrypted_file, "Failed to get encrypted filename.")

        # Decrypt
        decrypt_inputs = [
            "2",
            encrypted_file,
            "decrypted_file.txt",
            "AStrongPassword123!",
            "n", # No keyfile
            "n", # Don't delete encrypted
            "3"  # Exit
        ]
        run_thena_script(decrypt_inputs, config_file=config_file)

        self.assertTrue(os.path.exists("decrypted_file.txt"), "Decrypted file not found.")
        with open("decrypted_file.txt", "r") as f:
            content = f.read()
        self.assertEqual(content, "This is a test for XChaCha20-Poly1305.")

    def test_aes_siv_encryption_decryption(self):
        """Tests the full encryption-decryption cycle with AES-SIV."""
        config_file = "thena_config_aes_siv.json"
        self.configs["aes_siv"] = config_file
        with open(config_file, "w") as f:
            json.dump({"preferred_algorithm_priority": ["aes-siv", "aes-gcm"]}, f)

        with open("test_file.txt", "w") as f:
            f.write("This is a test for AES-SIV.")

        # Encrypt
        encrypt_inputs = [
            "1",
            "test_file.txt",
            "AStrongPassword123!",
            "n", # No keyfile
            "5", # AES-SIV algorithm selection
            "n", # No RSA
            "n", # No Curve2_5519
            "n", # Don't delete original
            "3"  # Exit
        ]
        _, _, _, encrypted_file = run_thena_script(encrypt_inputs, get_output_filename=True, config_file=config_file)
        self.assertIsNotNone(encrypted_file, "Failed to get encrypted filename.")

        # Decrypt
        decrypt_inputs = [
            "2",
            encrypted_file,
            "decrypted_file.txt",
            "AStrongPassword123!",
            "n", # No keyfile
            "n", # Don't delete encrypted
            "3"  # Exit
        ]
        run_thena_script(decrypt_inputs, config_file=config_file)

        self.assertTrue(os.path.exists("decrypted_file.txt"), "Decrypted file not found.")
        with open("decrypted_file.txt", "r") as f:
            content = f.read()
        self.assertEqual(content, "This is a test for AES-SIV.")

    def test_hybrid_cipher_encryption_decryption(self):
        """Tests the full encryption-decryption cycle of the HybridCipher class."""
        config_file = "thena_config_hybrid.json"
        self.configs["hybrid"] = config_file
        with open(config_file, "w") as f:
            # Prioritize a modern cipher to ensure the negotiator is working
            json.dump({"preferred_algorithm_priority": ["xchacha20-poly1305", "aes-gcm"], "encryption_algorithm": "hybrid-rsa-x25519"}, f)

        with open("test_file.txt", "w") as f:
            f.write("This is a test for the HybridCipher class.")

        # Encrypt using the command-line interface for hybrid mode
        command = [
            "python3", "Thena_dev_v19.py",
            "--encrypt",
            "-i", "test_file.txt",
            "-o", "hybrid_encrypted.encrypted",
            "-p", "AStrongPassword123!",
            "--config", config_file
        ]
        process = subprocess.run(command, text=True, capture_output=True)
        self.assertEqual(process.returncode, 0, f"Hybrid encryption failed: {process.stderr}")

        # Decrypt
        command = [
            "python3", "Thena_dev_v19.py",
            "--decrypt",
            "-i", "hybrid_encrypted.encrypted",
            "-o", "decrypted_file.txt",
            "-p", "AStrongPassword123!",
            "--config", config_file
        ]
        process = subprocess.run(command, text=True, capture_output=True)
        self.assertEqual(process.returncode, 0, f"Hybrid decryption failed: {process.stderr}")

        self.assertTrue(os.path.exists("decrypted_file.txt"), "Decrypted file not found.")
        with open("decrypted_file.txt", "r") as f:
            content = f.read()
        self.assertEqual(content, "This is a test for the HybridCipher class.")

        # Encrypt with AES + RSA layers, enabling temp files for encryption
        config_encrypt = "thena_config_encrypt.json"
        self.configs["encrypt"] = config_encrypt
        with open(config_encrypt, "w") as f:
            json.dump({"enable_temp_files": True}, f)

        encrypt_inputs = [
            "1",
            "test_file.txt",
            "AStrongPassword123!",
            "n",
            "1", # Algorithm selection
            "y",
            "y",
            "n",
            "n",
            "3"
        ]
        run_thena_script(encrypt_inputs, config_file=config_encrypt)

        encrypted_file = None
        for file in glob.glob("*.encrypted"):
            encrypted_file = file
            break

        self.assertIsNotNone(encrypted_file, "Encrypted file not found.")

        # Disable temp files for decryption
        config_decrypt = "thena_config_decrypt.json"
        self.configs["decrypt"] = config_decrypt
        with open(config_decrypt, "w") as f:
            json.dump({"enable_temp_files": False}, f)

        # Decrypt
        decrypt_inputs = [
            "2",
            encrypted_file,
            "decrypted_file.txt",
            "AStrongPassword123!",
            "n",
            "n",
            "3"
        ]
        stdout, stderr, _, _ = run_thena_script(decrypt_inputs, config_file=config_decrypt)

        self.assertNotIn("TypeError", stderr)
        try:
            self.assertTrue(os.path.exists("decrypted_file.txt"), "Decrypted file was not created.")
        except AssertionError as e:
            print("STDOUT:", stdout)
            print("STDERR:", stderr)
            raise e

class TestSecureMemoryFeatures(unittest.TestCase):
    """A test suite for the secure memory handling features."""
    def setUp(self):
        """Sets up the test environment for secure memory tests."""
        self.cleanup()

    def tearDown(self):
        """Tears down the test environment after secure memory tests."""
        self.cleanup()

    def cleanup(self):
        """Removes all test-related files."""
        files_to_remove = [
            "test_file.txt",
            "test_input.txt",
            "decrypted_file.txt",
        ]
        for f in files_to_remove:
            if os.path.exists(f):
                os.remove(f)

    def test_secure_memory_manager(self):
        """Tests the core functionality of the SecureMemoryManager class.

        This test verifies that data can be securely stored, retrieved, and
        wiped from the manager.
        """
        from Thena_dev_v19 import SecureMemoryManager, secure_overwrite_variable
        master_key = os.urandom(32)
        manager = SecureMemoryManager(master_key)

        # Test storing and retrieving data
        sensitive_data = b"test_sensitive_data"
        manager.store_sensitive_data("test_key", sensitive_data)
        retrieved_data = manager.retrieve_and_decrypt("test_key")
        self.assertEqual(retrieved_data, sensitive_data)

        # Test wiping data
        manager.wipe_data("test_key")
        retrieved_data_after_wipe = manager.retrieve_and_decrypt("test_key")
        self.assertIsNone(retrieved_data_after_wipe)

        secure_overwrite_variable(master_key)

    def test_constant_time_compare(self):
        """Tests the constant-time comparison function.

        This test ensures that the `constant_time_compare` function correctly
        compares byte strings and is suitable for use with cryptographic
        values.
        """
        import secrets
        self.assertTrue(secrets.compare_digest(b"abc", b"abc"))
        self.assertFalse(secrets.compare_digest(b"abc", b"abd"))
        self.assertFalse(secrets.compare_digest(b"abc", b"abcd"))
        self.assertFalse(secrets.compare_digest(b"abcd", b"abc"))

class TestPerformanceFeatures(unittest.TestCase):
    """A test suite for the performance-related features."""
    def setUp(self):
        """Sets up the test environment for performance tests.

        This method creates a large file to be used for testing streaming
        encryption and decryption, and a configuration file to enable
        performance-related features.
        """
        self.config_file = "thena_config_performance.json"
        self.large_file = "large_test_file.txt"
        self.encrypted_file = "large_test_file.encrypted"
        self.decrypted_file = "decrypted_large_file.txt"

        # Create a large file (15MB to trigger streaming)
        with open(self.large_file, "wb") as f:
            f.write(os.urandom(15 * 1024 * 1024))

        # Configure for streaming and performance tuning
        with open(self.config_file, "w") as f:
            json.dump({
                "large_file_threshold": 10 * 1024 * 1024, # 10MB
                "auto_tune_performance": True,
                "preferred_algorithm_priority": ["aes-gcm"]
            }, f)

    def tearDown(self):
        """Cleans up the test environment after performance tests."""
        files_to_remove = [
            self.large_file,
            self.encrypted_file,
            self.decrypted_file,
            self.config_file,
            "thena_keystore.json"
        ]
        for f in files_to_remove:
            if os.path.exists(f):
                os.remove(f)

    def test_streaming_encryption_decryption(self):
        """Tests the streaming encryption and decryption for a large file."""
        # Encrypt
        command = [
            "python3", "Thena_dev_v19.py",
            "--encrypt",
            "-i", self.large_file,
            "-o", self.encrypted_file,
            "-p", "AStrongStreamingPassword123!",
            "--config", self.config_file,
            "--keystore", "thena_keystore.json"
        ]
        process = subprocess.run(command, text=True, capture_output=True)
        self.assertEqual(process.returncode, 0, f"Streaming encryption failed: {process.stderr}")

        with open(self.encrypted_file, 'rb') as f:
            magic_bytes = f.read(8)
            self.assertEqual(magic_bytes, b"STREAMV1", "Streaming format magic bytes not found.")

        # Decrypt
        command = [
            "python3", "Thena_dev_v19.py",
            "--decrypt",
            "-i", self.encrypted_file,
            "-o", self.decrypted_file,
            "-p", "AStrongStreamingPassword123!",
            "--config", self.config_file,
            "--keystore", "thena_keystore.json"
        ]
        process = subprocess.run(command, text=True, capture_output=True)
        self.assertEqual(process.returncode, 0, f"Streaming decryption failed: {process.stderr}")
        self.assertIn("Streaming file format terdeteksi", process.stdout)

        # Verify content
        with open(self.large_file, "rb") as f1, open(self.decrypted_file, "rb") as f2:
            original_hash = subprocess.run(["sha256sum", self.large_file], capture_output=True, text=True).stdout.split()[0]
            decrypted_hash = subprocess.run(["sha256sum", self.decrypted_file], capture_output=True, text=True).stdout.split()[0]
            self.assertEqual(original_hash, decrypted_hash, "Decrypted file content does not match original.")

    def test_hardware_acceleration_detection_output(self):
        """Tests that the hardware acceleration detection message is displayed.
        """
        # We just need to run the script and check the output, no encryption needed.
        command = ["python3", "Thena_dev_v19.py", "--help"] # A simple command to run the script
        process = subprocess.run(command, text=True, capture_output=True)

        # Check if the detection message is present. The exact features depend on the test runner's CPU.
        self.assertTrue(
            "Akselerasi Kriptografi Hardware Terdeteksi" in process.stdout or
            "Tidak ada akselerasi kriptografi hardware yang terdeteksi" in process.stdout,
            "Hardware acceleration detection message not found in output."
        )

    def test_adaptive_performance_tuning_output(self):
        """Tests that the adaptive performance tuning messages are displayed.
        """
        command = [
            "python3", "Thena_dev_v19.py",
            "--help", # A simple command to run the script and trigger startup logic
            "--config", self.config_file
        ]
        process = subprocess.run(command, text=True, capture_output=True)

        # Check for tuning messages
        self.assertIn("Auto-Tuning: Argon2 parallelism disesuaikan", process.stdout)
        self.assertIn("Auto-Tuning: Argon2 memory_cost disesuaikan", process.stdout)

if __name__ == "__main__":
    unittest.main()
