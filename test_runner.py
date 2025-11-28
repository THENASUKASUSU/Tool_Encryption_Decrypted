
import subprocess
import os
import time
import unittest
import glob
import json
import hashlib
from Enkripsi import config

def run_thena_script(inputs, get_output_filename=False, config_file=None):
    """Runs the Thena script in a subprocess with a given set of inputs."""
    if "6" not in inputs:
        inputs.append("6")

    print(f"\n--- Running test with inputs: {inputs} ---")
    input_str = "\n".join(inputs) + "\n"

    command = ["python3", "-u", "Enkripsi.py"]
    if config_file:
        command.extend(["--config", config_file])

    start_time = time.time()
    result = subprocess.run(
        command,
        input=input_str,
        capture_output=True,
        text=True,
        timeout=60
    )
    stdout = result.stdout
    stderr = result.stderr
    end_time = time.time()

    print("STDOUT:", stdout)
    print("STDERR:", stderr)

    output_filename = None
    if get_output_filename:
        for line in stdout.split('\n'):
            if "berhasil dienkripsi ke" in line:
                try:
                    # Extracts filename from "File '...' berhasil dienkripsi ke '...'"
                    output_filename = line.split("'")[3]
                    break
                except IndexError:
                    # Fallback for different output formats
                    parts = line.split()
                    if len(parts) > 1 and parts[-1].endswith(".encrypted"):
                        output_filename = parts[-1]
                        break
    # A more reliable way if the output is just the filename
    if not output_filename and stdout.strip().endswith(".encrypted"):
        output_filename = stdout.strip()


    return stdout, stderr, end_time - start_time, output_filename

class TestThenaScript(unittest.TestCase):
    """A test suite for the main Thena script."""
    def setUp(self):
        """Sets up the test environment before each test."""
        self.cleanup()
        self.test_config_path = "test_config.json"
        with open(self.test_config_path, "w") as f:
            json.dump({
                "argon2_time_cost": 1, "argon2_memory_cost": 8, "argon2_parallelism": 1,
                "pbkdf2_iterations": 1, "scrypt_n": 2,
                "auto_tune_performance": False, "log_level": "DEBUG",
                "enable_temp_files": True
            }, f)

    def tearDown(self):
        """Tear down after the tests."""
        self.cleanup()

    def cleanup(self):
        """Remove all test-related files."""
        import shutil
        files_to_remove = [
            "test_file.txt", "test_input.txt", "decrypted_file.txt",
            "rsa_private_key.pem", "x25519_private_key.pem",
            ".master_key_encrypted", "thena_encryptor.log",
            "test_config.json", "hybrid_encrypted.encrypted",
            "thena_keystore.json"
        ]
        for f in files_to_remove:
            if os.path.exists(f):
                try: os.remove(f)
                except OSError: pass
        for file in glob.glob("*.encrypted"):
            try: os.remove(file)
            except OSError: pass
        if os.path.exists("./temp_thena"):
            shutil.rmtree("./temp_thena")

    def test_logging_in_interactive_mode(self):
        """Tests that logging works correctly in interactive mode."""
        with open("test_file.txt", "w") as f: f.write("log test")
        encrypt_inputs = ["1", "test_file.txt", "test_file.encrypted", "AStrongPassword123!", "n", "1", "n", "n", "n", ""]
        run_thena_script(encrypt_inputs, config_file=self.test_config_path)
        self.assertTrue(os.path.exists("thena_encryptor.log"))
        with open("thena_encryptor.log", "r") as f: log_content = f.read()
        self.assertIn("Memulai enkripsi file (simple)", log_content)

    def test_no_temp_files_left_after_decryption(self):
        """Tests that no temporary files are left after a layered decryption."""
        with open("test_file.txt", "w") as f: f.write("layered decryption")
        encrypt_inputs = ["1", "test_file.txt", "test_file.encrypted", "AStrongPassword123!", "n", "1", "y", "y", "n", ""]
        run_thena_script(encrypt_inputs, config_file=self.test_config_path)
        self.assertTrue(os.path.exists("test_file.encrypted"))
        decrypt_inputs = ["2", "test_file.encrypted", "decrypted_file.txt", "AStrongPassword123!", "n", "n", ""]
        run_thena_script(decrypt_inputs, config_file=self.test_config_path)
        self.assertTrue(os.path.exists("decrypted_file.txt"))
        if os.path.exists("./temp_thena"): self.assertEqual(len(os.listdir("./temp_thena")), 0)

    def test_xchacha20_poly1305_encryption_decryption(self):
        """Tests the full encryption-decryption cycle with XChaCha20-Poly1305."""
        with open("test_file.txt", "w") as f: f.write("Test XChaCha20")
        encrypt_inputs = ["1", "test_file.txt", "test_file.encrypted", "AStrongPassword123!", "n", "4", "n", "n", "n", ""]
        _, _, _, encrypted_file = run_thena_script(encrypt_inputs, get_output_filename=True, config_file=self.test_config_path)
        self.assertTrue(os.path.exists("test_file.encrypted"))
        decrypt_inputs = ["2", "test_file.encrypted", "decrypted_file.txt", "AStrongPassword123!", "n", "n", ""]
        run_thena_script(decrypt_inputs, config_file=self.test_config_path)
        with open("decrypted_file.txt", "r") as f: self.assertEqual(f.read(), "Test XChaCha20")

    def test_aes_siv_encryption_decryption(self):
        """Tests the full encryption-decryption cycle with AES-SIV."""
        with open("test_file.txt", "w") as f: f.write("Test AES-SIV")
        encrypt_inputs = ["1", "test_file.txt", "test_file.encrypted", "AStrongPassword123!", "n", "5", "n", "n", "n", ""]
        _, _, _, encrypted_file = run_thena_script(encrypt_inputs, get_output_filename=True, config_file=self.test_config_path)
        self.assertTrue(os.path.exists("test_file.encrypted"))
        decrypt_inputs = ["2", "test_file.encrypted", "decrypted_file.txt", "AStrongPassword123!", "n", "n", ""]
        run_thena_script(decrypt_inputs, config_file=self.test_config_path)
        with open("decrypted_file.txt", "r") as f: self.assertEqual(f.read(), "Test AES-SIV")

    def test_hybrid_cipher_encryption_decryption(self):
        """Tests the full encryption-decryption cycle of the HybridCipher class."""
        with open("test_file.txt", "w") as f: f.write("Test Hybrid")
        cmd = ["python3", "Enkripsi.py", "--encrypt", "-i", "test_file.txt", "-o", "hybrid.enc", "-p", "AStrongPassword123!", "--config", self.test_config_path]
        subprocess.run(cmd, text=True, check=True)
        cmd = ["python3", "Enkripsi.py", "--decrypt", "-i", "hybrid.enc", "-o", "decrypted.txt", "-p", "AStrongPassword123!", "--config", self.test_config_path]
        subprocess.run(cmd, text=True, check=True)
        with open("decrypted.txt", "r") as f: self.assertEqual(f.read(), "Test Hybrid")
        os.remove("hybrid.enc")
        os.remove("decrypted.txt")

    def test_duplicate_file_handling(self):
        """Tests the overwrite confirmation for both encryption and decryption."""
        with open("test_file.txt", "w") as f: f.write("Initial content.")
        encrypt_inputs = ["1", "test_file.txt", "test_file.encrypted", "AStrongPassword123!", "n", "1", "n", "n", "n", ""]
        run_thena_script(encrypt_inputs, config_file=self.test_config_path)
        self.assertTrue(os.path.exists("test_file.encrypted"))
        original_mtime = os.path.getmtime("test_file.encrypted")
        time.sleep(0.1)
        encrypt_decline = ["1", "test_file.txt", "test_file.encrypted", "n", ""]
        stdout, _, _, _ = run_thena_script(encrypt_decline, config_file=self.test_config_path)
        self.assertIn("Operasi dibatalkan", stdout)
        self.assertEqual(os.path.getmtime("test_file.encrypted"), original_mtime)
        time.sleep(0.1)
        encrypt_accept = ["1", "test_file.txt", "test_file.encrypted", "y", "AStrongPassword123!", "n", "1", "n", "n", "n", ""]
        run_thena_script(encrypt_accept, config_file=self.test_config_path)
        self.assertGreater(os.path.getmtime("test_file.encrypted"), original_mtime)
        with open("decrypted_file.txt", "w") as f: f.write("Overwrite this.")
        original_mtime = os.path.getmtime("decrypted_file.txt")
        time.sleep(0.1)
        decrypt_decline = ["2", "test_file.encrypted", "decrypted_file.txt", "n", ""]
        stdout, _, _, _ = run_thena_script(decrypt_decline, config_file=self.test_config_path)
        self.assertIn("Operasi dibatalkan", stdout)
        self.assertEqual(os.path.getmtime("decrypted_file.txt"), original_mtime)
        time.sleep(0.1)
        decrypt_accept = ["2", "test_file.encrypted", "decrypted_file.txt", "y", "AStrongPassword123!", "n", "n", ""]
        run_thena_script(decrypt_accept, config_file=self.test_config_path)
        self.assertGreater(os.path.getmtime("decrypted_file.txt"), original_mtime)
        with open("decrypted_file.txt", "r") as f: self.assertEqual(f.read(), "Initial content.")

class TestSecureMemoryFeatures(unittest.TestCase):
    def setUp(self): self.cleanup()
    def tearDown(self): self.cleanup()
    def cleanup(self):
        for f in ["test_file.txt", "test_input.txt", "decrypted_file.txt"]:
            if os.path.exists(f): os.remove(f)

    def test_constant_time_compare(self):
        import secrets
        self.assertTrue(secrets.compare_digest(b"abc", b"abc"))
        self.assertFalse(secrets.compare_digest(b"abc", b"abd"))

class TestPerformanceFeatures(unittest.TestCase):
    def setUp(self):
        self.cleanup()
        self.test_config_path = "perf_config.json"
        with open(self.test_config_path, "w") as f:
            json.dump({"large_file_threshold": 1024, "auto_tune_performance": False,
                       "argon2_time_cost": 1, "argon2_memory_cost": 8, "argon2_parallelism": 1}, f)
        self.large_file = "large.bin"
        with open(self.large_file, "wb") as f: f.write(os.urandom(2 * 1024))
        self.encrypted_file = self.large_file + ".enc"
        self.decrypted_file = "decrypted_large.bin"

    def tearDown(self):
        self.cleanup()

    def cleanup(self):
        """More robust cleanup."""
        files_to_check = ['large_file', 'encrypted_file', 'decrypted_file', 'test_config_path']
        for attr_name in files_to_check:
            if hasattr(self, attr_name):
                file_path = getattr(self, attr_name)
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except OSError:
                        pass
        # Always try to remove this
        if os.path.exists("thena_keystore.json"):
            os.remove("thena_keystore.json")


    def test_streaming_encryption_decryption(self):
        cmd = ["python3", "Enkripsi.py", "--encrypt", "-i", self.large_file, "-o", self.encrypted_file, "-p", "AStrongPassword123!", "--config", self.test_config_path]
        subprocess.run(cmd, text=True, check=True)
        cmd = ["python3", "Enkripsi.py", "--decrypt", "-i", self.encrypted_file, "-o", self.decrypted_file, "-p", "AStrongPassword123!", "--config", self.test_config_path]
        res = subprocess.run(cmd, text=True, capture_output=True, check=True)
        self.assertIn("Streaming file format terdeteksi", res.stdout)
        with open(self.large_file, "rb") as f1, open(self.decrypted_file, "rb") as f2:
            self.assertEqual(hashlib.sha256(f1.read()).hexdigest(), hashlib.sha256(f2.read()).hexdigest())

    def test_hardware_acceleration_detection_output(self):
        stdout, _ = run_thena_script(["6"], config_file=self.test_config_path)[:2]
        self.assertTrue("Akselerasi Kriptografi" in stdout or "Tidak ada akselerasi" in stdout)

    def test_adaptive_performance_tuning_output(self):
        tuning_config = "tuning_config.json"
        with open(tuning_config, "w") as f: json.dump({"auto_tune_performance": True}, f)
        stdout, _ = run_thena_script(["6"], config_file=tuning_config)[:2]
        self.assertIn("Auto-Tuning", stdout)
        os.remove(tuning_config)

if __name__ == "__main__":
    unittest.main()
