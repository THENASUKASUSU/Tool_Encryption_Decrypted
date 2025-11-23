
import subprocess
import os
import time
import unittest
import glob
import json

def run_thena_script(inputs, get_output_filename=False, config_file=None):
    """Runs the Thena script with the given inputs."""
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
    def setUp(self):
        """Set up for the tests."""
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
            "n",  # Use RSA? (y/N)
            "n",  # Use Curve25519? (y/N)
            "n",  # Delete original file? (y/N)
            "3",  # Exit
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

if __name__ == "__main__":
    unittest.main()
