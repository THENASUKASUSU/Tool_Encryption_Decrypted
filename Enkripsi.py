#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Versi: 18.2 (Refactored)
"""
import json
import os
import sys
import secrets
import time
import logging
import hashlib
import stat
import base64
import argparse
import zlib
import hmac
import platform
import tempfile
import atexit
import gc
import threading
import ctypes
import ctypes.util
import signal
import mmap
from pathlib import Path
from abc import ABC, abstractmethod

# --- Kode Warna ANSI ---
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"

# --- Dynamic Library Imports ---
CRYPTOGRAPHY_AVAILABLE = False
PYCRYPTODOME_AVAILABLE = False
ARGON2_AVAILABLE = False
MISCREANT_AVAILABLE = False
PYNACL_AVAILABLE = False
CPUINFO_AVAILABLE = False
PSUTIL_AVAILABLE = False

try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography import exceptions as crypto_exceptions
    CRYPTOGRAPHY_AVAILABLE = True
    print(f"{GREEN}✅ Modul 'cryptography' ditemukan.{RESET}")
except ImportError:
    print(f"{RED}❌ Modul 'cryptography' tidak ditemukan. Beberapa fitur akan dinonaktifkan.{RESET}")

if not CRYPTOGRAPHY_AVAILABLE:
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        PYCRYPTODOME_AVAILABLE = True
        print(f"{YELLOW}⚠️  Menggunakan 'pycryptodome' sebagai fallback untuk AES.{RESET}")
    except ImportError:
        print(f"{RED}❌ 'pycryptodome' juga tidak ditemukan. Fungsionalitas AES terbatas.{RESET}")

try:
    from argon2 import PasswordHasher, exceptions as argon2_exceptions
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
    print(f"{GREEN}✅ Modul 'argon2' ditemukan.{RESET}")
except ImportError:
    print(f"{RED}❌ Modul 'argon2' tidak ditemukan. Argon2 KDF tidak tersedia.{RESET}")

try:
    from miscreant.aes.siv import SIV
    MISCREANT_AVAILABLE = True
    print(f"{GREEN}✅ Modul 'miscreant' ditemukan. AES-SIV Tersedia.{RESET}")
except ImportError:
    print(f"{RED}❌ Modul 'miscreant' tidak ditemukan. AES-SIV Dinonaktifkan.{RESET}")

try:
    import nacl.secret
    import nacl.utils
    PYNACL_AVAILABLE = True
    print(f"{GREEN}✅ Modul 'pynacl' ditemukan. XChaCha20-Poly1305 Tersedia.{RESET}")
except ImportError:
    print(f"{RED}❌ Modul 'pynacl' tidak ditemukan. XChaCha20-Poly1305 Dinonaktifkan.{RESET}")

try:
    import psutil
    PSUTIL_AVAILABLE = True
    print(f"{GREEN}✅ Modul 'psutil' ditemukan.{RESET}")
except ImportError:
    print(f"{YELLOW}⚠️  Modul 'psutil' tidak tersedia. Auto-tuning dinonaktifkan.{RESET}")

try:
    import cpuinfo
    CPUINFO_AVAILABLE = True
    print(f"{GREEN}✅ Modul 'cpuinfo' ditemukan.{RESET}")
except ImportError:
    print(f"{YELLOW}⚠️  Modul 'cpuinfo' tidak tersedia. Deteksi hardware dinonaktifkan.{RESET}")


# --- Global Constants & Configuration ---
CONFIG_FILE = "thena_config_v18.json"
LOG_FILE = "thena_encryptor.log"
# File format magic bytes
FILE_MAGIC = b"THENA_V2"


# --- Refactored Core Classes ---

class ThreadSafeGlobal:
    """Manages thread-safe global state and resources."""
    def __init__(self):
        self._lock = threading.RLock()
        self._temp_files_created = set()
        self._memory_manager = None
        # For runtime integrity checks
        self._integrity_hashes = {}
        self._critical_functions = []
        self._integrity_thread = None
        self._stop_integrity_check = threading.Event()
        atexit.register(self.cleanup)

    def add_temp_file(self, file_path: str):
        with self._lock:
            self._temp_files_created.add(file_path)

    def set_memory_manager(self, manager):
        with self._lock:
            self._memory_manager = manager

    @property
    def memory_manager(self):
        with self._lock:
            return self._memory_manager

    def register_critical_function(self, func):
        with self._lock:
            if func and callable(func) and func not in self._critical_functions:
                self._critical_functions.append(func)
                code_hash = calculate_code_hash(func)
                if code_hash:
                    self._integrity_hashes[func.__name__] = code_hash
                    logger.debug(f"Fungsi kritis '{func.__name__}' didaftarkan.")

    def _verify_integrity(self):
        with self._lock:
            for func in self._critical_functions:
                current_hash = calculate_code_hash(func)
                stored_hash = self._integrity_hashes.get(func.__name__)
                if stored_hash and current_hash != stored_hash:
                    logger.critical(f"PELANGGARAN INTEGRITAS: Kode fungsi '{func.__name__}' telah diubah!")
                    return False
            return True

    def start_integrity_checker(self, interval: int):
        if self._integrity_thread and self._integrity_thread.is_alive():
            return
        
        def _checker_loop():
            while not self._stop_integrity_check.wait(interval):
                if not self._verify_integrity():
                    print_error_box("PELANGGARAN INTEGRITAS TERDETEKSI! PROGRAM DIHENTIKAN.")
                    os._exit(1)
        
        self._integrity_thread = threading.Thread(target=_checker_loop, daemon=True)
        self._integrity_thread.start()
        logger.info(f"Pengecek integritas runtime dimulai (interval: {interval} detik).")

    def _stop_integrity_checker(self):
        self._stop_integrity_check.set()
        if self._integrity_thread and self._integrity_thread.is_alive():
            self._integrity_thread.join(timeout=1.0)

    def cleanup(self):
        """Comprehensive cleanup of all managed resources."""
        self._stop_integrity_checker()
        with self._lock:
            # Cleanup temp files
            temp_files = list(self._temp_files_created)
            for temp_file in temp_files:
                try:
                    if os.path.exists(temp_file):
                        os.unlink(temp_file)
                except OSError:
                    pass # Ignore errors on cleanup
            self._temp_files_created.clear()

            # Cleanup memory manager
            if self._memory_manager and hasattr(self._memory_manager, 'cleanup'):
                self._memory_manager.cleanup()
            self._memory_manager = None

globals_manager = ThreadSafeGlobal()


class KeyProvider(ABC):
    """Abstract base class for providing encryption keys."""
    @abstractmethod
    def get_key(self, salt: bytes) -> tuple[bytes | None, int]:
        """
        Derives or retrieves the encryption key.
        Returns the key and the key version (if applicable).
        """
        pass

class PasswordKeyProvider(KeyProvider):
    """Provides a key derived from a password and optional keyfile."""
    def __init__(self, password: str, keyfile_path: str | None = None):
        if not password:
            raise ValueError("Password cannot be empty.")
        self.password = password
        self.keyfile_path = keyfile_path

    def get_key(self, salt: bytes) -> tuple[bytes | None, int]:
        key = derive_key_from_password_and_keyfile(self.password, salt, self.keyfile_path)
        return key, 0 # Version is 0 for password-based keys

class MasterKeyProvider(KeyProvider):
    """Provides a key from the KeyManager."""
    def __init__(self, key_manager, key_version: int | None = None):
        self.key_manager = key_manager
        self.key_version = key_version

    def get_key(self, salt: bytes) -> tuple[bytes | None, int]:
        """
        Salt is ignored for master key operations as the key is pre-existing.
        It's used for deriving a unique header key.
        """
        try:
            if self.key_version is not None:
                # Decryption: use specified version
                key = self.key_manager.get_key_by_version(self.key_version)
                return key, self.key_version
            else:
                # Encryption: use active version
                active_version = self.key_manager.get_active_key_version()
                key = self.key_manager.get_active_key()
                return key, active_version
        except ValueError as e:
            logger.error(f"Master key retrieval failed: {e}")
            return None, -1


# --- Configuration & Logging ---

def load_config():
    """Loads the configuration from a JSON file with secure defaults."""
    default_config = {
        "preferred_algorithm_priority": ["xchacha20-poly1305", "aes-gcm", "chacha20-poly1305", "aes-siv"],
        "kdf_type": "argon2id",
        "argon2_time_cost": 16,
        "argon2_memory_cost": 1048576, # 1 GB
        "argon2_parallelism": 4,
        "scrypt_n": 2**20,
        "scrypt_r": 8,
        "scrypt_p": 1,
        "pbkdf2_iterations": 600000,
        "chunk_size": 1 * 1024 * 1024, # 1 MB
        "file_key_length": 32,
        "gcm_nonce_len": 12,
        "gcm_tag_len": 16,
        "log_level": "INFO",
        "temp_dir": "./temp_thena",
        "large_file_threshold": 50 * 1024 * 1024, # 50 MB
        "auto_tune_performance": True,
        "enable_secure_memory": True,
        "header_derivation_info": "thena_header_enc_key_v2",
        "file_key_derivation_info": "thena_file_key_v2"
    }
    config_path = Path(CONFIG_FILE)
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                loaded_config = json.load(f)
            # Merge defaults with loaded config
            config = default_config.copy()
            config.update(loaded_config)
            print(f"{CYAN}Konfigurasi dimuat dari {CONFIG_FILE}{RESET}")
            return config
        except (json.JSONDecodeError, IOError):
            print(f"{RED}Error membaca {CONFIG_FILE}, menggunakan nilai default.{RESET}")
            return default_config
    else:
        # Create default config file
        try:
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=4)
            print(f"{CYAN}File konfigurasi default '{CONFIG_FILE}' dibuat.{RESET}")
        except IOError:
            print(f"{RED}Gagal membuat file konfigurasi. Menggunakan default sementara.{RESET}")
        return default_config

def setup_logging(level_str: str):
    """Configures logging for the application."""
    level = getattr(logging, level_str.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
        force=True
    )
    return logging.getLogger(__name__)

config = load_config()
logger = setup_logging(config["log_level"])


# --- Core Cryptographic Logic ---

def derive_key_from_password_and_keyfile(
    password: str, salt: bytes, keyfile_path: str = None, kdf_params: dict = None
) -> bytes | None:
    """
    Derives a key using the configured KDF.
    An optional kdf_params dict can override global config for specific operations.
    """
    params = kdf_params or config
    kdf_type = params.get("kdf_type", "argon2id").lower()
    password_bytes = password.encode('utf-8')
    keyfile_bytes = b""

    if keyfile_path:
        try:
            with open(keyfile_path, 'rb') as kf:
                keyfile_bytes = kf.read()
        except IOError as e:
            logger.error(f"Gagal membaca keyfile '{keyfile_path}': {e}")
            return None

    combined_input = password_bytes + keyfile_bytes

    try:
        if kdf_type == "argon2id" and ARGON2_AVAILABLE:
            return hash_secret_raw(
                secret=combined_input, salt=salt,
                time_cost=params["argon2_time_cost"],
                memory_cost=params["argon2_memory_cost"],
                parallelism=params["argon2_parallelism"],
                hash_len=params["file_key_length"], type=Type.ID
            )
        elif kdf_type == "scrypt" and CRYPTOGRAPHY_AVAILABLE:
            kdf = Scrypt(salt=salt, length=params["file_key_length"], n=params["scrypt_n"], r=params["scrypt_r"], p=params["scrypt_p"])
            return kdf.derive(combined_input)
        elif kdf_type == "pbkdf2" and CRYPTOGRAPHY_AVAILABLE:
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=params["file_key_length"], salt=salt, iterations=params["pbkdf2_iterations"])
            return kdf.derive(combined_input)
        else:
            logger.error(f"KDF '{kdf_type}' tidak tersedia. Cek instalasi library.")
            if CRYPTOGRAPHY_AVAILABLE:
                logger.warning("Fallback ke PBKDF2.")
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=params["file_key_length"], salt=salt, iterations=params["pbkdf2_iterations"])
                return kdf.derive(combined_input)
            return None
    except Exception as e:
        logger.error(f"Gagal menurunkan kunci dengan {kdf_type}: {e}")
        return None

def derive_key_with_hkdf(base_key: bytes, salt: bytes, info: bytes, length: int) -> bytes | None:
    """Derives a key using HKDF-SHA256."""
    if not CRYPTOGRAPHY_AVAILABLE:
        logger.error("HKDF memerlukan library 'cryptography'.")
        return None
    try:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
        return hkdf.derive(base_key)
    except Exception as e:
        logger.error(f"Gagal menurunkan kunci dengan HKDF: {e}")
        return None


class AlgorithmNegotiator:
    """Selects the best available encryption algorithm."""
    @staticmethod
    def get_best_algorithm() -> str | None:
        """Selects the best available AEAD algorithm based on config priority."""
        supported = {
            "xchacha20-poly1305": PYNACL_AVAILABLE,
            "aes-gcm": CRYPTOGRAPHY_AVAILABLE,
            "chacha20-poly1305": CRYPTOGRAPHY_AVAILABLE,
            "aes-siv": MISCREANT_AVAILABLE,
        }
        for algo in config.get("preferred_algorithm_priority", []):
            if supported.get(algo):
                logger.info(f"Algoritma terpilih: {algo}")
                return algo
        logger.error("Tidak ada algoritma enkripsi AEAD yang tersedia.")
        return None

class SecureMemoryManager:
    """Manages sensitive data in memory by encrypting it when not in use."""
    def __init__(self, master_key):
        if not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError("SecureMemoryManager requires 'cryptography' library.")
        self._master_key = master_key
        self._enclave = {}
        self._lock = threading.RLock()

    def _derive_data_key(self, key_id: str) -> bytes:
        """Derives a unique key for a piece of data using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32, # AES-256 key
            salt=key_id.encode('utf-8'),
            info=b'secure-memory-manager-data-key'
        )
        return hkdf.derive(self._master_key)

    def _encrypt(self, key: bytes, data: bytes) -> bytes:
        """Encrypts data with AES-GCM."""
        nonce = secrets.token_bytes(12)
        cipher = AESGCM(key)
        encrypted_data = cipher.encrypt(nonce, data, None)
        return nonce + encrypted_data

    def _decrypt(self, key: bytes, encrypted_data: bytes) -> bytes:
        """Decrypts data with AES-GCM."""
        nonce = encrypted_data[:12]
        data = encrypted_data[12:]
        cipher = AESGCM(key)
        return cipher.decrypt(nonce, data, None)

    def store_sensitive_data(self, key_id: str, data: bytes):
        """Encrypts and stores sensitive data."""
        with self._lock:
            derived_key = self._derive_data_key(key_id)
            encrypted_data = self._encrypt(derived_key, data)
            self._enclave[key_id] = encrypted_data
            # Securely wipe the derived key
            ctypes.memset(ctypes.addressof(ctypes.create_string_buffer(derived_key)), 0, len(derived_key))

    def retrieve_and_decrypt(self, key_id: str) -> bytes | None:
        """Retrieves and decrypts sensitive data."""
        with self._lock:
            encrypted_data = self._enclave.get(key_id)
            if encrypted_data is None:
                return None

            derived_key = self._derive_data_key(key_id)
            try:
                decrypted_data = self._decrypt(derived_key, encrypted_data)
                return decrypted_data
            except crypto_exceptions.InvalidTag:
                logger.error(f"Failed to decrypt sensitive data for '{key_id}'.")
                return None
            finally:
                # Securely wipe the derived key
                ctypes.memset(ctypes.addressof(ctypes.create_string_buffer(derived_key)), 0, len(derived_key))

    def wipe_data(self, key_id: str):
        """Securely wipes a piece of data from the manager."""
        with self._lock:
            if key_id in self._enclave:
                data_ref = self._enclave[key_id]
                ctypes.memset(ctypes.addressof(ctypes.create_string_buffer(data_ref)), 0, len(data_ref))
                del self._enclave[key_id]

    def cleanup(self):
        """Securely wipes all stored data and the master key."""
        with self._lock:
            for key_id in list(self._enclave.keys()):
                self.wipe_data(key_id)
            if self._master_key:
                ctypes.memset(ctypes.addressof(ctypes.create_string_buffer(self._master_key)), 0, len(self._master_key))
            self._master_key = None
            self._enclave.clear()
        gc.collect()
        logger.info("SecureMemoryManager cleaned up successfully.")

class KeyManager:
    """Manages key versions, rotation, and an encrypted keystore."""
    def __init__(self, keystore_path: str, password: str, keyfile_path: str | None = None):
        self.keystore_path = keystore_path
        self.password = password
        self.keyfile_path = keyfile_path
        self._lock = threading.RLock()
        self.keystore = self._load_or_initialize_keystore()

    def _derive_keystore_key(self, salt: bytes) -> bytes | None:
        """Derives the keystore encryption key using stable, non-tuned parameters."""
        # Using hardcoded parameters is crucial for keystore stability
        stable_params = {
            "kdf_type": "argon2id",
            "argon2_time_cost": 16,
            "argon2_memory_cost": 262144, # 256 MB
            "argon2_parallelism": 4,
            "file_key_length": 32,
        }
        return derive_key_from_password_and_keyfile(
            self.password, salt, self.keyfile_path, kdf_params=stable_params
        )

    def _load_or_initialize_keystore(self) -> dict:
        """Loads the keystore from file or creates a new one."""
        with self._lock:
            if os.path.exists(self.keystore_path):
                try:
                    with open(self.keystore_path, 'rb') as f:
                        salt = f.read(32)
                        nonce = f.read(12)
                        encrypted_data = f.read()

                    keystore_key = self._derive_keystore_key(salt)
                    if keystore_key is None:
                        raise ValueError("Gagal menurunkan kunci keystore.")

                    cipher = AESGCM(keystore_key)
                    decrypted_data = cipher.decrypt(nonce, encrypted_data, None)
                    return json.loads(decrypted_data.decode('utf-8'))
                except (IOError, ValueError, json.JSONDecodeError, crypto_exceptions.InvalidTag) as e:
                    logger.critical(f"Gagal memuat keystore: {e}. Password salah atau file rusak.", exc_info=True)
                    print_error_box("Gagal memuat keystore. Password/Keyfile salah atau file rusak.")
                    sys.exit(1)
            else:
                logger.info(f"Keystore tidak ditemukan di '{self.keystore_path}'. Membuat yang baru.")
                new_keystore = {
                    "keys": {},
                    "active_key_version": 0,
                    "config_hash": "" # To detect config changes
                }
                self.keystore = new_keystore
                self._generate_new_key(is_initial_key=True)
                self._save_keystore()
                print(f"{GREEN}Keystore baru berhasil dibuat di '{self.keystore_path}'.{RESET}")
                return self.keystore

    def _save_keystore(self):
        """Encrypts and saves the current keystore state to file."""
        with self._lock:
            salt = secrets.token_bytes(32)
            keystore_key = self._derive_keystore_key(salt)
            if keystore_key is None:
                logger.error("Gagal menyimpan keystore: Gagal menurunkan kunci.")
                return

            keystore_bytes = json.dumps(self.keystore, indent=2).encode('utf-8')
            cipher = AESGCM(keystore_key)
            nonce = secrets.token_bytes(12)
            encrypted_data = cipher.encrypt(nonce, keystore_bytes, None)

            try:
                with open(self.keystore_path, 'wb') as f:
                    f.write(salt)
                    f.write(nonce)
                    f.write(encrypted_data)
            except IOError as e:
                logger.error(f"Gagal menyimpan keystore ke disk: {e}")

    def _generate_new_key(self, is_initial_key=False):
        """Generates a new master key and adds it to the keystore."""
        new_version = 1 if is_initial_key else self.keystore["active_key_version"] + 1
        new_key = secrets.token_bytes(config["file_key_length"])

        self.keystore["keys"][str(new_version)] = {
            "key": base64.b64encode(new_key).decode('utf-8'),
            "created": time.time()
        }
        self.keystore["active_key_version"] = new_version
        logger.info(f"Kunci master baru versi {new_version} dibuat.")

    def rotate_key(self):
        """Rotates the master key."""
        with self._lock:
            print(f"{CYAN}Merotasi kunci master...{RESET}")
            old_version = self.keystore['active_key_version']
            self._generate_new_key()
            self._save_keystore()
            print(f"{GREEN}Rotasi kunci berhasil. Versi aktif sekarang: {self.keystore['active_key_version']} (sebelumnya: {old_version}).{RESET}")

    def get_active_key(self) -> bytes:
        """Returns the active master key in bytes."""
        with self._lock:
            active_version = str(self.keystore["active_key_version"])
            key_b64 = self.keystore["keys"][active_version]["key"]
            return base64.b64decode(key_b64)

    def get_key_by_version(self, version: int) -> bytes:
        """Returns a specific master key by version."""
        with self._lock:
            key_info = self.keystore["keys"].get(str(version))
            if not key_info:
                raise ValueError(f"Kunci versi {version} tidak ditemukan di keystore.")
            return base64.b64decode(key_info["key"])

    def get_active_key_version(self) -> int:
        """Returns the active master key version number."""
        with self._lock:
            return self.keystore["active_key_version"]

# --- Unified Streaming Function ---
def process_file_stream(
    mode: str,
    input_path: str,
    output_path: str,
    key_provider: KeyProvider,
    algorithm: str | None = None
):
    """
    Unified function to encrypt or decrypt a file using a streaming approach.

    Args:
        mode (str): 'encrypt' or 'decrypt'.
        input_path (str): Path to the source file.
        output_path (str): Path to the destination file.
        key_provider (KeyProvider): The provider for the base encryption key.
        algorithm (str, optional): The symmetric algorithm to use for encryption.
                                   Required for 'encrypt' mode.
    Returns:
        bool: True on success, False on failure.
    """
    if mode == 'encrypt' and not algorithm:
        logger.error("Mode enkripsi memerlukan spesifikasi algoritma.")
        return False

    chunk_size = config["chunk_size"]
    salt_len = config["file_key_length"]
    tag_len = config["gcm_tag_len"]
    gcm_nonce_len = config["gcm_nonce_len"]

    try:
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            if mode == 'encrypt':
                # --- ENCRYPTION LOGIC ---
                salt = secrets.token_bytes(salt_len)
                base_key, key_version = key_provider.get_key(salt)
                if not base_key:
                    return False

                # Derive a unique key for the header encryption
                header_salt = secrets.token_bytes(salt_len)
                header_key = derive_key_with_hkdf(base_key, header_salt, config["header_derivation_info"].encode(), 32)
                if not header_key:
                    return False

                # Calculate checksum of original file
                f_in.seek(0)
                checksum = hashlib.sha256()
                while chunk := f_in.read(chunk_size):
                    checksum.update(chunk)
                original_checksum = checksum.digest()
                f_in.seek(0)

                # Prepare header
                header_data = {
                    "algo": algorithm,
                    "checksum": original_checksum.hex(),
                    "key_version": key_version
                }
                header_bytes = json.dumps(header_data).encode()

                # Encrypt header (using one-shot AESGCM as headers are small)
                header_nonce = secrets.token_bytes(gcm_nonce_len)
                header_cipher = AESGCM(header_key)
                encrypted_header = header_cipher.encrypt(header_nonce, header_bytes, None)

                # Derive file key for payload encryption
                file_key = derive_key_with_hkdf(base_key, salt, config["file_key_derivation_info"].encode(), 32)
                if not file_key: return False

                # Write file header to output
                f_out.write(FILE_MAGIC)
                f_out.write(salt)
                f_out.write(header_salt)
                f_out.write(header_nonce)
                f_out.write(len(encrypted_header).to_bytes(4, 'big'))
                f_out.write(encrypted_header)

                # Encrypt payload using low-level streaming API
                payload_nonce = secrets.token_bytes(gcm_nonce_len)
                cipher = Cipher(algorithms.AES(file_key), modes.GCM(payload_nonce))
                encryptor = cipher.encryptor()
                
                f_out.write(payload_nonce)

                while chunk := f_in.read(chunk_size):
                    encrypted_chunk = encryptor.update(chunk)
                    f_out.write(encrypted_chunk)

                final_chunk = encryptor.finalize()
                f_out.write(final_chunk)
                f_out.write(encryptor.tag)
                logger.info(f"Enkripsi '{input_path}' berhasil.")

            elif mode == 'decrypt':
                # --- DECRYPTION LOGIC ---
                magic = f_in.read(len(FILE_MAGIC))
                if magic != FILE_MAGIC:
                    logger.error("Format file tidak valid atau rusak (magic bytes salah).")
                    return False

                salt = f_in.read(salt_len)
                header_salt = f_in.read(salt_len)
                header_nonce = f_in.read(gcm_nonce_len)
                encrypted_header_len = int.from_bytes(f_in.read(4), 'big')
                encrypted_header = f_in.read(encrypted_header_len)

                # Temporarily derive a key to decrypt the header. We might need to re-derive if using master key
                temp_base_key, _ = key_provider.get_key(salt)
                if not temp_base_key: return False

                header_key = derive_key_with_hkdf(temp_base_key, header_salt, config["header_derivation_info"].encode(), 32)
                if not header_key: return False

                header_cipher = AESGCM(header_key)
                try:
                    header_bytes = header_cipher.decrypt(header_nonce, encrypted_header, None)
                    header_data = json.loads(header_bytes)
                    key_version = header_data.get("key_version", 0)

                    # If using MasterKeyProvider, now we get the correctly versioned key
                    if isinstance(key_provider, MasterKeyProvider):
                        key_provider.key_version = key_version

                    base_key, _ = key_provider.get_key(salt)
                    if not base_key: return False

                except (crypto_exceptions.InvalidTag, json.JSONDecodeError, KeyError) as e:
                    logger.error(f"Gagal mendekripsi header. Kunci salah atau file rusak: {e}")
                    return False

                # Derive file key for payload decryption
                file_key = derive_key_with_hkdf(base_key, salt, config["file_key_derivation_info"].encode(), 32)
                if not file_key: return False

                # Read payload components
                payload_nonce = f_in.read(gcm_nonce_len)
                
                # We need to read the tag from the very end of the file
                f_in.seek(-tag_len, os.SEEK_END)
                tag = f_in.read(tag_len)

                # Seek back to the beginning of the ciphertext
                ciphertext_start_pos = len(FILE_MAGIC) + salt_len * 2 + gcm_nonce_len + 4 + encrypted_header_len + gcm_nonce_len
                f_in.seek(ciphertext_start_pos)

                # Decrypt payload using low-level streaming API
                cipher = Cipher(algorithms.AES(file_key), modes.GCM(payload_nonce, tag))
                decryptor = cipher.decryptor()
                calculated_checksum = hashlib.sha256()

                while True:
                    current_pos = f_in.tell()
                    end_pos = os.fstat(f_in.fileno()).st_size - tag_len
                    if current_pos >= end_pos:
                        break

                    bytes_to_read = min(chunk_size, end_pos - current_pos)
                    encrypted_chunk = f_in.read(bytes_to_read)

                    decrypted_chunk = decryptor.update(encrypted_chunk)
                    f_out.write(decrypted_chunk)
                    calculated_checksum.update(decrypted_chunk)

                final_chunk = decryptor.finalize() # Verifies the tag
                f_out.write(final_chunk)
                calculated_checksum.update(final_chunk)

                # Verify checksum
                stored_checksum = bytes.fromhex(header_data["checksum"])
                if hmac.compare_digest(calculated_checksum.digest(), stored_checksum):
                    logger.info(f"Dekripsi dan verifikasi '{input_path}' berhasil.")
                else:
                    logger.error("Checksum tidak cocok! File mungkin telah diubah.")
                    # Clean up partially written file
                    f_out.close()
                    os.remove(output_path)
                    return False
        return True
    except (IOError, OSError) as e:
        logger.error(f"Operasi file gagal: {e}")
        return False
    except (crypto_exceptions.InvalidTag, ValueError) as e:
        logger.error(f"Operasi kriptografi gagal (kunci salah atau file rusak): {e}")
        return False
    except Exception as e:
        logger.critical(f"Terjadi error tak terduga: {e}", exc_info=True)
        return False


# --- Security Hardening Functions ---

def calculate_code_hash(func) -> str:
    """Calculates the SHA-256 hash of a function's bytecode for integrity checks."""
    try:
        import dis
        bytecode = dis.Bytecode(func).dis()
        return hashlib.sha256(bytecode.encode('utf-8')).hexdigest()
    except Exception as e:
        logger.warning(f"Gagal menghitung hash untuk fungsi '{func.__name__}': {e}")
        return ""

def check_pydevd() -> bool:
    """Checks for the presence of the PyCharm debugger."""
    return 'pydevd' in sys.modules or 'pydevd_pycharm' in sys.modules

def check_ptrace() -> bool:
    """Checks if the current process is being traced (on Linux)."""
    if platform.system() != "Linux":
        return False
    try:
        with open(f"/proc/{os.getpid()}/status") as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    # If TracerPid is not 0, a debugger is attached.
                    return int(line.split()[1]) != 0
    except (IOError, OSError):
        return False # Cannot check, assume not debugged
    return False

def detect_debugging():
    """Detects if a debugger is attached."""
    if config.get("enable_anti_debug", False):
        if check_pydevd() or check_ptrace():
            logger.critical("LINGKUNGAN DEBUGGING TERDETEKSI! PROGRAM AKAN DIHENTIKAN.")
            print_error_box("LINGKUNGAN DEBUGGING TERDETEKSI! PROGRAM AKAN DIHENTIKAN.")
            # Use os._exit for immediate termination without cleanup
            os._exit(1)

def tune_argon2_params():
    """Dynamically adjusts Argon2 parameters based on system resources."""
    if not config.get("auto_tune_performance", False) or not PSUTIL_AVAILABLE:
        return

    try:
        available_mem_gb = psutil.virtual_memory().available / (1024**3)
        cpu_cores = psutil.cpu_count(logical=False) or 1

        # Tune memory cost (memory_cost is in KiB)
        if available_mem_gb > 8:
            config["argon2_memory_cost"] = 2 * 1024 * 1024 # 2 GB
        elif available_mem_gb > 4:
            config["argon2_memory_cost"] = 1 * 1024 * 1024 # 1 GB
        elif available_mem_gb > 2:
            config["argon2_memory_cost"] = 512 * 1024 # 512 MB
        else:
            config["argon2_memory_cost"] = 256 * 1024 # 256 MB

        # Tune parallelism
        config["argon2_parallelism"] = max(1, cpu_cores // 2)

        logger.info(f"Parameter Argon2 disesuaikan: memory_cost={config['argon2_memory_cost']}KiB, parallelism={config['argon2_parallelism']}")
        print(f"{CYAN}Auto-tuning: Parameter Argon2 disesuaikan untuk sistem Anda.{RESET}")

    except Exception as e:
        logger.warning(f"Gagal melakukan auto-tuning parameter Argon2: {e}")

def detect_hardware_acceleration():
    """Detects CPU features for hardware-accelerated cryptography."""
    if not CPUINFO_AVAILABLE:
        return
    try:
        info = cpuinfo.get_cpu_info()
        flags = info.get('flags', [])
        if 'aes' in flags:
            logger.info("Akselerasi hardware AES-NI terdeteksi.")
            print(f"{GREEN}✅ Akselerasi hardware AES-NI terdeteksi.{RESET}")
        else:
            logger.warning("AES-NI tidak terdeteksi.")
    except Exception as e:
        logger.warning(f"Gagal mendeteksi fitur hardware: {e}")


# --- Helper & UI Functions ---

def print_error_box(message: str):
    """Prints a formatted error message."""
    print(f"\n{RED}{BOLD}╭─{'─' * (len(message) + 2)}─╮")
    print(f"│  {message}  │")
    print(f"╰─{'─' * (len(message) + 2)}─╯{RESET}")

def confirm_overwrite(file_path: str) -> bool:
    """Asks for user confirmation to overwrite a file."""
    if os.path.exists(file_path):
        confirm = input(f"{YELLOW}File '{file_path}' sudah ada. Timpa? (y/N): {RESET}").strip().lower()
        return confirm in ['y', 'yes']
    return True

def secure_wipe_file(file_path: str, passes: int = 3):
    """Securely wipes a file by overwriting it with random data."""
    if not os.path.exists(file_path):
        return
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            os.remove(file_path)
            return
        with open(file_path, "r+b") as f:
            for i in range(passes):
                f.seek(0)
                # Overwrite with random data, last pass with zeros
                data = secrets.token_bytes(file_size) if i < passes - 1 else b'\x00' * file_size
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        os.remove(file_path)
        logger.info(f"File '{file_path}' berhasil dihapus secara aman.")
    except (IOError, OSError) as e:
        logger.error(f"Gagal menghapus file '{file_path}' secara aman: {e}")


# --- Refactored Interactive and Main Logic ---

def interactive_process(mode: str):
    """Handles the interactive encryption or decryption process."""
    try:
        action_word = "enkripsi" if mode == 'encrypt' else "dekripsi"
        input_path = input(f"{BOLD}Masukkan path file untuk di-{action_word}: {RESET}").strip()
        if not os.path.isfile(input_path):
            print_error_box("File input tidak ditemukan.")
            return

        default_output = f"{input_path}.encrypted" if mode == 'encrypt' else input_path.replace('.encrypted', '')
        output_path = input(f"{BOLD}Masukkan path file output [{default_output}]: {RESET}").strip() or default_output
        if not confirm_overwrite(output_path):
            return

        password = input(f"{BOLD}Masukkan kata sandi: {RESET}").strip()
        if not password:
            print_error_box("Kata sandi tidak boleh kosong.")
            return

        use_keyfile = input(f"{BOLD}Gunakan Keyfile? (y/N): {RESET}").strip().lower()
        keyfile_path = None
        if use_keyfile in ['y', 'yes']:
            keyfile_path = input(f"{BOLD}Masukkan path Keyfile: {RESET}").strip()
            if not os.path.isfile(keyfile_path):
                print_error_box("File keyfile tidak ditemukan.")
                return

        provider = PasswordKeyProvider(password, keyfile_path)
        success = False
        if mode == 'encrypt':
            algo = AlgorithmNegotiator.get_best_algorithm()
            if not algo: return
            success = process_file_stream('encrypt', input_path, output_path, provider, algo)
        else: # decrypt
            success = process_file_stream('decrypt', input_path, output_path, provider)

        if success:
            print(f"{GREEN}✅ Operasi {action_word} berhasil diselesaikan.{RESET}")
            if mode == 'encrypt':
                delete_original = input(f"{BOLD}Hapus file asli secara aman? (y/N): {RESET}").strip().lower()
                if delete_original in ['y', 'yes']:
                    secure_wipe_file(input_path)
        else:
            print_error_box(f"Operasi {action_word} gagal.")

    except Exception as e:
        logger.error(f"Error pada mode interaktif: {e}", exc_info=True)
        print_error_box(f"Terjadi error tak terduga: {e}")

def interactive_mode():
    """Main loop for the interactive user interface."""
    while True:
        print("\n" + "="*50)
        print(f"{CYAN}{BOLD}--- MENU UTAMA ---{RESET}".center(60))
        print("="*50)
        print("1. Enkripsi File")
        print("2. Dekripsi File")
        print("3. Keluar")
        choice = input(f"{BOLD}Pilihan Anda: {RESET}").strip()

        if choice == '1':
            interactive_process('encrypt')
        elif choice == '2':
            interactive_process('decrypt')
        elif choice == '3':
            break
        else:
            print_error_box("Pilihan tidak valid.")
        input(f"\n{CYAN}Tekan Enter untuk kembali ke menu...{RESET}")

def main():
    """Main function to handle command-line arguments and interactive mode."""
    parser = argparse.ArgumentParser(
        description='Thena Dev Encryption Tool - Refactored',
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--encrypt', action='store_true', help='Mode enkripsi file.')
    group.add_argument('--decrypt', action='store_true', help='Mode dekripsi file.')
    group.add_argument('--rotate-key', action='store_true', help='Rotasi master key pada keystore.')

    parser.add_argument('-i', '--input', type=str, help='File input.')
    parser.add_argument('-o', '--output', type=str, help='File output.')
    parser.add_argument('-p', '--password', type=str, help='Password untuk enkripsi atau keystore.')
    parser.add_argument('-k', '--keyfile', type=str, help='Path ke keyfile (opsional).')
    parser.add_argument('--keystore', type=str, help='Path ke file keystore untuk menggunakan mode master key.')
    parser.add_argument('--config', type=str, help='Path to a custom config file (for testing).')


    if len(sys.argv) == 1:
        interactive_mode()
        sys.exit(0)

    args = parser.parse_args()

    # --- Initialize Hardening Features ---
    detect_debugging()
    detect_hardware_acceleration()
    tune_argon2_params()

    # Register critical functions for integrity checking
    globals_manager.register_critical_function(process_file_stream)
    globals_manager.register_critical_function(derive_key_from_password_and_keyfile)
    if config.get("enable_runtime_integrity", False):
        globals_manager.start_integrity_checker(config.get("integrity_check_interval", 15))


    # --- Mode Rotasi Kunci ---
    if args.rotate_key:
        if not all([args.keystore, args.password]):
            print_error_box("--keystore dan --password diperlukan untuk rotasi kunci.")
            sys.exit(1)
        try:
            key_manager = KeyManager(args.keystore, args.password, args.keyfile)
            key_manager.rotate_key()
            sys.exit(0)
        except Exception as e:
            logger.critical(f"Gagal merotasi kunci: {e}")
            sys.exit(1)

    # --- Mode Enkripsi/Dekripsi ---
    if not all([args.input, args.output, args.password]):
        parser.error("--input, --output, dan --password diperlukan untuk enkripsi/dekripsi.")

    if not (args.encrypt or args.decrypt):
        parser.error("Mode operasi --encrypt atau --decrypt harus dipilih.")

    key_provider: KeyProvider | None = None
    if args.keystore:
        key_manager = KeyManager(args.keystore, args.password, args.keyfile)
        key_provider = MasterKeyProvider(key_manager)
    else:
        key_provider = PasswordKeyProvider(args.password, args.keyfile)

    mode = 'encrypt' if args.encrypt else 'decrypt'
    algorithm = AlgorithmNegotiator.get_best_algorithm() if mode == 'encrypt' else None
    if mode == 'encrypt' and not algorithm:
        sys.exit(1)

    success = process_file_stream(mode, args.input, args.output, key_provider, algorithm)

    if success:
        print(f"\n{GREEN}✅ Operasi berhasil diselesaikan.{RESET}")
        print(f"   Input : {args.input}")
        print(f"   Output: {args.output}")
    else:
        print_error_box("Operasi gagal. Periksa log untuk detail.")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperasi dibatalkan oleh pengguna.")
        sys.exit(1)
    finally:
        globals_manager.cleanup()
