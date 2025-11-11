
import subprocess
import os
import unittest

class TestDecryption(unittest.TestCase):
    def setUp(self):
        # Create a dummy file for decryption
        with open("dummy_file.encrypted", "w") as f:
            f.write("dummy content")

    def tearDown(self):
        # Clean up the dummy file and master key if it exists
        if os.path.exists("dummy_file.encrypted"):
            os.remove("dummy_file.encrypted")
        if os.path.exists("decrypted_file.txt"):
            os.remove("decrypted_file.txt")
        if os.path.exists(".master_key_encrypted_v14"):
            os.remove(".master_key_encrypted_v14")
        if os.path.exists("thena_config_v14.json"):
            os.remove("thena_config_v14.json")
        if os.path.exists("thena_encryptor_v14.log"):
            os.remove("thena_encryptor_v14.log")


    def test_decrypt_without_master_key(self):
        # Run the script with --decrypt and check for the error message
        result = subprocess.run(
            [
                "python3",
                "Thena_dev.py",
                "--decrypt",
                "-i",
                "dummy_file.encrypted",
                "-o",
                "decrypted_file.txt",
                "-p",
                "S0meP@ssw0rd!",
            ],
            capture_output=True,
            text=True,
        )
        output = result.stdout + result.stderr
        self.assertIn("Error: File Master Key", output)
        self.assertIn("tidak ditemukan", output)

if __name__ == "__main__":
    unittest.main()
