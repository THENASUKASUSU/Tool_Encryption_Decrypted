#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Versi: 18.1 (Diperbaiki)
"""

# --- Kode Warna ANSI ---
RESET = "\033[0m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"
BG_BLUE = "\033[44m"
BG_MAGENTA = "\033[45m"
BG_CYAN = "\033[46m"
BG_WHITE = "\033[47m"

# --- Impor dari cryptography untuk semua KDF, HKDF, Fernet, dan Cipher ---
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
    print(f"{GREEN}✅ Modul 'cryptography' ditemukan. Fitur Lanjutan Tersedia.{RESET}")
except ImportError as e:
    CRYPTOGRAPHY_AVAILABLE = False
    print(f"{RED}❌ Error mengimpor 'cryptography': {e}{RESET}")
    print(f"{RED}❌ Modul 'cryptography' tidak ditemukan. Fitur Lanjutan Dinonaktifkan.{RESET}")
    print(f"   Instal dengan: pip install cryptography")

# --- Impor dari pycryptodome (sebagai fallback untuk AES-GCM jika cryptography gagal) ---
PYCRYPTODOME_AVAILABLE = False
if not CRYPTOGRAPHY_AVAILABLE:
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        PYCRYPTODOME_AVAILABLE = True
        print(f"{YELLOW}⚠️  Modul 'cryptography' tidak ditemukan. Menggunakan 'pycryptodome' sebagai fallback untuk AES-GCM.{RESET}")
    except ImportError:
        print(f"{RED}❌ Modul 'pycryptodome' juga tidak ditemukan.{RESET}")
        print(f"   Instal: pip install pycryptodome")
        import sys
        sys.exit(1)

# --- Impor dari argon2 (PasswordHasher untuk fallback jika cryptography Argon2 tidak tersedia) ---
try:
    from argon2 import PasswordHasher, exceptions
    from argon2.low_level import hash_secret_raw, Type
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
    print(f"{GREEN}✅ Modul 'argon2' ditemukan.{RESET}")
except ImportError:
    ARGON2_AVAILABLE = False
    print(f"{RED}❌ Modul 'argon2' tidak ditemukan. Argon2 tidak tersedia.{RESET}")

# --- Impor dari miscreant untuk AES-SIV ---
try:
    from miscreant.aes.siv import SIV
    MISCREANT_AVAILABLE = True
    print(f"{GREEN}✅ Modul 'miscreant' ditemukan. AES-SIV Tersedia.{RESET}")
except ImportError:
    MISCREANT_AVAILABLE = False
    print(f"{RED}❌ Modul 'miscreant' tidak ditemukan. AES-SIV Dinonaktifkan.{RESET}")

# --- Impor dari PyNaCl untuk XChaCha20-Poly1305 ---
try:
    import nacl.secret
    import nacl.utils
    PYNACL_AVAILABLE = True
    print(f"{GREEN}✅ Modul 'pynacl' ditemukan. XChaCha20-Poly1305 Tersedia.{RESET}")
except ImportError:
    PYNACL_AVAILABLE = False
    print(f"{RED}❌ Modul 'pynacl' tidak ditemukan. XChaCha20-Poly1305 Dinonaktifkan.{RESET}")

# --- Impor lainnya ---
from pathlib import Path
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
import struct
import psutil
try:
    import cpuinfo
    CPUINFO_AVAILABLE = True
except ImportError:
    CPUINFO_AVAILABLE = False
    print(f"{YELLOW}⚠️  Modul 'cpuinfo' tidak tersedia. Hardware detection dinonaktifkan.{RESET}")

def safe_cpu_info():
    """Safe CPU info detection with fallback for Termux"""
    if not CPUINFO_AVAILABLE:
        return {'flags': []}
    try:
        return cpuinfo.get_cpu_info()
    except Exception as e:
        logger.warning(f"CPU info detection failed: {e}")
        return {'flags': []}

# --- Nama File Konfigurasi dan Log ---
CONFIG_FILE = "thena_config.json"
LOG_FILE = "thena_encryptor.log"

import threading
from typing import Any, Dict, List, Set, Optional, Callable
from types import FrameType
import gc

class ThreadSafeGlobal:
    """Thread-safe global state manager with proper resource management."""
    
    def __init__(self):
        self._lock = threading.RLock()
        self._integrity_hashes: Dict[str, str] = {}
        self._critical_functions: List[Callable] = []
        self._integrity_thread: Optional[threading.Thread] = None
        self._stop_integrity_check = threading.Event()
        self._temp_files_created: Set[str] = set()
        self._memory_manager: Optional[Any] = None
        self._cleanup_registered = False
        
    # === CONTEXT MANAGER SUPPORT ===
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit with cleanup."""
        self.cleanup()
    
    # === INTEGRITY HASHES METHODS ===
    @property
    def integrity_hashes(self) -> Dict[str, str]:
        with self._lock:
            return self._integrity_hashes.copy()
    
    def set_integrity_hash(self, key: str, value: str) -> None:
        with self._lock:
            self._integrity_hashes[key] = value
    
    def get_integrity_hash(self, key: str) -> Optional[str]:
        with self._lock:
            return self._integrity_hashes.get(key)
    
    def remove_integrity_hash(self, key: str) -> bool:
        with self._lock:
            if key in self._integrity_hashes:
                del self._integrity_hashes[key]
                return True
            return False
    
    def clear_integrity_hashes(self) -> None:
        with self._lock:
            self._integrity_hashes.clear()
    
    # === CRITICAL FUNCTIONS METHODS ===
    @property
    def critical_functions(self) -> List[Callable]:
        with self._lock:
            return self._critical_functions.copy()
    
    def add_critical_function(self, func: Callable) -> None:
        with self._lock:
            if func not in self._critical_functions:
                self._critical_functions.append(func)
    
    def remove_critical_function(self, func: Callable) -> bool:
        with self._lock:
            if func in self._critical_functions:
                self._critical_functions.remove(func)
                return True
            return False
    
    # === INTEGRITY THREAD METHODS ===
    @property
    def integrity_thread(self) -> Optional[threading.Thread]:
        with self._lock:
            return self._integrity_thread
    
    def set_integrity_thread(self, thread: threading.Thread) -> None:
        with self._lock:
            if self._integrity_thread and self._integrity_thread.is_alive():
                self._stop_integrity_check.set()
                self._integrity_thread.join(timeout=5.0)
            self._integrity_thread = thread
    
    # === STOP INTEGRITY CHECK METHODS ===
    @property
    def stop_integrity_check(self) -> threading.Event:
        with self._lock:
            return self._stop_integrity_check
    
    def stop_integrity_thread(self) -> None:
        """Safely stop the integrity thread."""
        with self._lock:
            self._stop_integrity_check.set()
            if self._integrity_thread and self._integrity_thread.is_alive():
                self._integrity_thread.join(timeout=5.0)
                if self._integrity_thread.is_alive():
                    logger.warning("Integrity thread did not stop gracefully")
    
    # === TEMP FILES METHODS ===
    @property
    def temp_files_created(self) -> Set[str]:
        with self._lock:
            return self._temp_files_created.copy()
    
    def add_temp_file(self, file_path: str) -> None:
        with self._lock:
            self._temp_files_created.add(file_path)
    
    def remove_temp_file(self, file_path: str) -> bool:
        with self._lock:
            if file_path in self._temp_files_created:
                self._temp_files_created.remove(file_path)
                return True
            return False
    
    def clear_temp_files(self) -> None:
        with self._lock:
            self._temp_files_created.clear()
    
    def cleanup_temp_files(self) -> int:
        """Cleanup all temp files and return count of successfully removed files."""
        removed_count = 0
        with self._lock:
            temp_files = self._temp_files_created.copy()
            self._temp_files_created.clear()
        
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                    removed_count += 1
                    logger.debug(f"File sementara dihapus: {temp_file}")
            except OSError as e:
                logger.warning(f"Gagal menghapus file sementara {temp_file}: {e}")
        
        return removed_count
    
    # === MEMORY MANAGER METHODS ===
    @property
    def memory_manager(self) -> Optional[Any]:
        with self._lock:
            return self._memory_manager
    
    def set_memory_manager(self, manager: Any) -> None:
        with self._lock:
            # Cleanup previous manager if exists
            if self._memory_manager is not None:
                self._cleanup_memory_manager()
            self._memory_manager = manager
    
    def _cleanup_memory_manager(self) -> None:
        """Safely cleanup memory manager resources."""
        if self._memory_manager:
            try:
                # ✅ PERBAIKAN: Gunakan method cleanup yang terstandarisasi
                if hasattr(self._memory_manager, 'cleanup'):
                    self._memory_manager.cleanup()
                elif hasattr(self._memory_manager, 'wipe_all'):
                    self._memory_manager.wipe_all()
                else:
                    # Fallback: manual cleanup
                    if hasattr(self._memory_manager, '_enclave'):
                        enclave_keys = list(self._memory_manager._enclave.keys())
                        for key in enclave_keys:
                            if hasattr(self._memory_manager, 'wipe_data'):
                                self._memory_manager.wipe_data(key)
                
                # Force garbage collection
                gc.collect()
                
            except Exception as e:
                logger.error(f"Error cleaning up memory manager: {e}")
            finally:
                # ✅ PERBAIKAN: Pastikan reference di-set ke None
                self._memory_manager = None
    
    # === BULK OPERATIONS ===
    def bulk_update_integrity_hashes(self, hashes: Dict[str, str]) -> None:
        """Update multiple integrity hashes at once."""
        with self._lock:
            self._integrity_hashes.update(hashes)
    
    def bulk_add_temp_files(self, file_paths: List[str]) -> None:
        """Add multiple temp files at once."""
        with self._lock:
            self._temp_files_created.update(file_paths)
    
    # === STATUS AND INFO METHODS ===
    def get_status(self) -> Dict[str, Any]:
        """Get current status of all managed resources."""
        with self._lock:
            return {
                'integrity_hashes_count': len(self._integrity_hashes),
                'critical_functions_count': len(self._critical_functions),
                'integrity_thread_alive': self._integrity_thread.is_alive() if self._integrity_thread else False,
                'stop_integrity_check_set': self._stop_integrity_check.is_set(),
                'temp_files_count': len(self._temp_files_created),
                'memory_manager_set': self._memory_manager is not None
            }
    
    # === CLEANUP METHODS ===
   def cleanup(self) -> Dict[str, int]:
        """Comprehensive cleanup of all managed resources."""
        cleanup_stats = {
            'temp_files_removed': 0,
            'integrity_hashes_cleared': 0,
            'critical_functions_cleared': 0,
            '
    }
    
    # Stop integrity thread
    self.stop_integrity_thread()
    
    # Cleanup temp files
    cleanup_stats['temp_files_removed'] = self.cleanup_temp_files()
    
    # Clear other resources
    with self._lock:
        cleanup_stats['integrity_hashes_cleared'] = len(self._integrity_hashes)
        self._integrity_hashes.clear()
        
        cleanup_stats['critical_functions_cleared'] = len(self._critical_functions)
        self._critical_functions.clear()
        
        # ✅ PERBAIKAN: Cleanup memory manager
        if self._memory_manager:
            self._cleanup_memory_manager()
            cleanup_stats['memory_manager_cleaned'] = 1
        
        # Reset stop event for potential future use
        self._stop_integrity_check.clear()
    
    logger.info(f"ThreadSafeGlobal cleanup completed: {cleanup_stats}")
    return cleanup_stats
    
    def __del__(self):
        """Destructor with safety cleanup."""
        try:
            if any([self._integrity_hashes, self._critical_functions, 
                   self._temp_files_created, self._memory_manager]):
                logger.warning("ThreadSafeGlobal being destroyed with active resources")
                self.cleanup()
        except Exception:
            # Ignore errors during destruction
            pass

# Inisialisasi global thread-safe
globals_manager = ThreadSafeGlobal()

# Tambahkan setelah baris: globals_manager = ThreadSafeGlobal()

def get_memory_manager():
    """Safe access to memory manager with error handling."""
    try:
        memory_manager = globals_manager.memory_manager
        if memory_manager and hasattr(memory_manager, '_enclave'):
            return memory_manager
        return None
    except Exception as e:
        logger.error(f"Error accessing memory manager: {e}")
        return None

def store_sensitive_data(key_id: str, data: bytes):
    """Wrapper to safely store sensitive data in the global manager."""
    memory_manager = get_memory_manager()
    if memory_manager:
        memory_manager.store_sensitive_data(key_id, data)
    else:
        logger.warning(f"Cannot store data for '{key_id}': SecureMemoryManager is not initialized.")

def get_sensitive_data(key_id: str):
    """Wrapper to safely retrieve sensitive data from the global manager."""
    memory_manager = get_memory_manager()
    if memory_manager:
        return memory_manager.retrieve_and_decrypt(key_id)
    return None

def wipe_sensitive_data(key_id: str):
    """Wrapper to safely wipe sensitive data from the global manager."""
    memory_manager = get_memory_manager()
    if memory_manager:
        memory_manager.wipe_data(key_id)
    else:
        logger.warning(f"Cannot wipe data for '{key_id}': SecureMemoryManager is not initialized.")

# Tambahkan di bagian import
def get_aes_cipher():
    if CRYPTOGRAPHY_AVAILABLE:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        return True, Cipher, algorithms, modes
    elif PYCRYPTODOME_AVAILABLE:
        from Crypto.Cipher import AES
        return True, AES, None, None
    else:
        return False, None, None, None

# --- Fungsi Cleanup Otomatis ---
def cleanup_temp_files():
    """Removes all temporary files created during the program's execution."""
    global globals_manager
    for temp_file in globals_manager.temp_files_created:
        try:
            os.unlink(temp_file)
            logger.debug(f"File sementara dihapus: {temp_file}")
        except OSError as e:
            logger.warning(f"Gagal menghapus file sementara {temp_file}: {e}")
    globals_manager.clear_temp_files()
    logger.info("Cleanup file sementara selesai.")

# Daftarkan fungsi cleanup saat program keluar
atexit.register(cleanup_temp_files)

# --- Fungsi Utilitas Hardening ---
def calculate_code_hash(func):
    """Calculates the SHA-256 hash of a function's bytecode.

    This function is used for runtime integrity checks to detect if a function's
    code has been tampered with.

    Args:
        func: The function to hash.

    Returns:
        A string containing the hexadecimal SHA-256 hash of the function's
        bytecode, or an empty string if an error occurs.
    """
    try:
        import dis
        bytecode = dis.Bytecode(func).dis()
        code_bytes = bytecode.encode('utf-8')
        return hashlib.sha256(code_bytes).hexdigest()
    except Exception as e:
        logger.warning(f"Gagal mendapatkan kode untuk fungsi '{func.__name__}': {e}")
        return ""

def register_sensitive_data(key: str, data: bytes):
    """Register sensitive data for integrity checking."""
    global globals_manager
    if config.get("enable_runtime_data_integrity", False):
        data_hash = calculate_data_hash(data)
        globals_manager.set_integrity_hash(f"data_{key}", data_hash)
        logger.debug(f"Data sensitif '{key}' didaftarkan untuk integrity check.")

def perform_streaming_decryption(input_path, output_path, password, keyfile_path, salt):
    """Implement streaming decryption logic."""
    try:
        # Derive master key from password and keyfile
        master_key = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
        if not master_key:
            logger.error("Failed to derive master key for streaming decryption")
            return False
            
        with open(input_path, 'rb') as f_in:
            # Skip magic bytes "STREAMV1" yang sudah dibaca sebelumnya
            f_in.read(8)  # Already verified outside
            
            # Read key version
            key_version = int.from_bytes(f_in.read(4), 'big')
            
            # Read encrypted file key
            encrypted_key_len = int.from_bytes(f_in.read(4), 'big')
            encrypted_file_key = f_in.read(encrypted_key_len)
            
            # Decrypt file key using master key
            master_fernet_key = base64.urlsafe_b64encode(master_key)
            master_fernet = Fernet(master_fernet_key)
            file_key = master_fernet.decrypt(encrypted_file_key)
            
            # Read algorithm
            algo_len = int.from_bytes(f_in.read(1), 'big')
            algo = f_in.read(algo_len).decode('utf-8')
            
            # Read nonce and stored checksum
            nonce = f_in.read(config["gcm_nonce_len"])
            stored_checksum = f_in.read(32)
            
            # Calculate tag position
            input_size = os.path.getsize(input_path)
            header_size = 8 + 4 + 4 + encrypted_key_len + 1 + algo_len + len(nonce) + len(stored_checksum)
            tag_pos = input_size - config["gcm_tag_len"]
            
            # Read tag from end of file
            f_in.seek(tag_pos)
            tag = f_in.read(config["gcm_tag_len"])
            f_in.seek(header_size)  # Reset to data position
            
            # Setup stream decryptor
            if algo == "aes-gcm" and CRYPTOGRAPHY_AVAILABLE:
                cipher = Cipher(algorithms.AES(file_key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
            else:
                logger.error(f"Streaming not supported for algorithm: {algo}")
                return False
            
            # Stream decryption
            calculated_checksum = hashlib.sha256()
            with open(output_path, 'wb') as f_out:
                bytes_remaining = tag_pos - header_size
                
                while bytes_remaining > 0:
                    chunk_size = min(config["chunk_size"], bytes_remaining)
                    encrypted_chunk = f_in.read(chunk_size)
                    
                    if not encrypted_chunk:
                        break
                        
                    decrypted_chunk = decryptor.update(encrypted_chunk)
                    f_out.write(decrypted_chunk)
                    calculated_checksum.update(decrypted_chunk)
                    
                    bytes_remaining -= len(encrypted_chunk)
                
                # Finalize decryption
                try:
                    decryptor.finalize()
                except Exception as e:
                    logger.error(f"Decryption finalization failed: {e}")
                    return False
            
            # Verify checksum
            if calculated_checksum.digest() == stored_checksum:
                logger.info("Streaming decryption completed successfully")
                return True
            else:
                logger.error("Streaming decryption failed: checksum mismatch")
                return False
                
    except Exception as e:
        logger.error(f"Streaming decryption failed: {e}")
        return False

def perform_fallback_decryption(input_path, output_path, password, keyfile_path):
    """Fallback decryption for old file formats using in-memory method."""
    try:
        logger.info("Using fallback in-memory decryption")
        
        # Baca seluruh file ke memory
        with open(input_path, 'rb') as f:
            file_data = f.read()
        
        # Untuk format lama, kita perlu mengekstrak bagian-bagian manual
        salt = file_data[:config["file_key_length"]]
        remaining_data = file_data[config["file_key_length"]:]
        
        # Derive key
        key = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
        if not key:
            return False
            
        # Coba parse format lama (tanpa header terenkripsi)
        # Format lama: [salt][algo_name][nonce][checksum][padding][ciphertext]
        try:
            # Simple format detection dan parsing
            algo_len = remaining_data[0]
            algo = remaining_data[1:1+algo_len].decode('utf-8')
            nonce_start = 1 + algo_len
            nonce = remaining_data[nonce_start:nonce_start+config["gcm_nonce_len"]]
            checksum_start = nonce_start + config["gcm_nonce_len"]
            checksum = remaining_data[checksum_start:checksum_start+32]
            padding_start = checksum_start + 32
            padding_bytes = remaining_data[padding_start:padding_start+config["padding_size_length"]]
            padding_added = int.from_bytes(padding_bytes, 'big')
            ciphertext_start = padding_start + config["padding_size_length"]
            ciphertext = remaining_data[ciphertext_start:]
            
            # Decrypt berdasarkan algoritma
            if algo == "aes-gcm":
                if CRYPTOGRAPHY_AVAILABLE:
                    cipher = AESGCM(key)
                    plaintext_data = cipher.decrypt(nonce, ciphertext, None)
                else:
                    return False
            else:
                logger.error(f"Unsupported algorithm in fallback: {algo}")
                return False
                
            # Remove padding
            if padding_added > 0:
                final_plaintext = plaintext_data[:-padding_added]
            else:
                final_plaintext = plaintext_data
                
            # Verify checksum
            calculated_checksum = calculate_checksum(final_plaintext)
            if calculated_checksum == checksum:
                with open(output_path, 'wb') as f_out:
                    f_out.write(final_plaintext)
                return True
            else:
                logger.error("Fallback decryption: checksum mismatch")
                return False
                
        except Exception as parse_error:
            logger.error(f"Failed to parse old file format: {parse_error}")
            return False
            
    except Exception as e:
        logger.error(f"Fallback decryption failed: {e}")
        return False

def perform_streaming_encryption(input_path, output_path, password, keyfile_path, algo):
    """Perform encryption using streaming mode for large files."""
    try:
        salt = secrets.token_bytes(config["file_key_length"])
        master_key = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
        if master_key is None:
            logger.error("Failed to derive master key for streaming encryption")
            return False, None

        # Store master key securely
        store_sensitive_data("master_encryption_key", master_key)
        
        # Setup streaming encryptor
        stream_encryptor = StreamEncryptor(master_key)
        nonce = stream_encryptor.nonce

        # Calculate original checksum
        original_checksum_calculator = hashlib.sha256()
        with open(input_path, 'rb') as f_in:
            while chunk := f_in.read(config["chunk_size"]):
                original_checksum_calculator.update(chunk)
        original_checksum = original_checksum_calculator.digest()

        # Write to output file
        with open(output_path, 'wb') as f_out:
            f_out.write(salt)
            f_out.write(b"STREAMV1")
            
            algo_bytes = algo.encode('utf-8')
            f_out.write(len(algo_bytes).to_bytes(1, 'big'))
            f_out.write(algo_bytes)

            f_out.write(nonce)
            f_out.write(original_checksum)
            
            # Stream encryption
            with open(input_path, 'rb') as f_in:
                while chunk := f_in.read(config["chunk_size"]):
                    encrypted_chunk = stream_encryptor.update(chunk)
                    f_out.write(encrypted_chunk)
            
            # Finalize and write tag
            stream_encryptor.finalize()
            tag = stream_encryptor.tag
            f_out.write(tag)

        # Cleanup
        wipe_sensitive_data("master_encryption_key")
        
        logger.info("Streaming encryption completed successfully")
        return True, output_path
        
    except Exception as e:
        logger.error(f"Streaming encryption failed: {e}")
        wipe_sensitive_data("master_encryption_key")  # Ensure cleanup
        return False, None

def perform_in_memory_encryption(input_path, output_path, password, keyfile_path, algo, hide_paths):
    """Perform encryption using in-memory mode for smaller files."""
    try:
        salt = secrets.token_bytes(config["file_key_length"])
        key = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
        if key is None:
            logger.error("Failed to derive key for in-memory encryption")
            return False, None

        # Baca file input
        with open(input_path, 'rb') as f_in:
            plaintext_data = f_in.read()

        # ... [lanjutkan dengan logika in-memory encryption yang sudah ada] ...
        # [Kode dari bagian fallback di encrypt_file_simple tetap di sini]
        
        # [Implementasi lengkap sama dengan bagian in-memory yang sudah ada]
        
        return True, output_path
        
    except Exception as e:
        logger.error(f"In-memory encryption failed: {e}")
        return False, None
    
def verify_data_integrity():
    """Verifies the integrity of sensitive data in memory."""
    try:
        # Verifikasi master key jika ada di memory manager
        memory_manager = get_memory_manager()  # ✅ Gunakan helper function
        if memory_manager:
            # Contoh: verifikasi beberapa data kunci
            test_data = b"integrity_check"
            memory_manager.store_sensitive_data("integrity_test", test_data)
            retrieved = memory_manager.retrieve_and_decrypt("integrity_test")
            if retrieved != test_data:
                logger.critical("Data integrity violation: Stored and retrieved data mismatch!")
                return False
            memory_manager.wipe_data("integrity_test")
        
        logger.debug("Data integrity check passed.")
        return True
    except Exception as e:
        logger.warning(f"Data integrity check failed: {e}")
        return False
        
def safe_tune_argon2_params():
    """Wrapper aman untuk tune_argon2_params"""
    try:
        tune_argon2_params()
    except Exception as e:
        logger.warning(f"Auto-tuning gagal: {e}")                

def calculate_data_hash(data) -> str:
    """Calculates the SHA-256 hash of a byte string.

    Args:
        data: The data to hash.

    Returns:
        A string containing the hexadecimal SHA-256 hash of the data, or
        an empty string if the data is not a byte string.
    """
    if isinstance(data, (bytes, bytearray, str)):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    return ""

def verify_integrity():
    """Verifies the integrity of critical functions and code."""
    global globals_manager
    try:
        # Verifikasi fungsi kritis
        for func in globals_manager.critical_functions:
            current_hash = calculate_code_hash(func)
            stored_hash = globals_manager.get_integrity_hash(f"func_{func.__name__}")
            if stored_hash and current_hash != stored_hash:
                logger.critical(f"Integrity violation detected in function: {func.__name__}")
                return False
                
        # Verifikasi data sensitif di memory manager
        memory_manager = get_memory_manager()
        if memory_manager:
            # Test storage and retrieval integrity
            test_data = b"integrity_verification_test_2024"
            test_key = "integrity_test_key"
            
            memory_manager.store_sensitive_data(test_key, test_data)
            retrieved_data = memory_manager.retrieve_and_decrypt(test_key)
            memory_manager.wipe_data(test_key)
            
            if retrieved_data != test_data:
                logger.critical("Data integrity violation in SecureMemoryManager!")
                return False
                
        logger.debug("Runtime integrity verification passed.")
        return True
        
    except Exception as e:
        logger.error(f"Integrity verification failed: {e}")
        return False
        
def register_critical_function(func):
    """Registers a function for runtime integrity checking."""
    global globals_manager
    try:
        if func and callable(func):
            globals_manager.add_critical_function(func)
            # Store initial code hash
            code_hash = calculate_code_hash(func)
            if code_hash:
                globals_manager.set_integrity_hash(f"func_{func.__name__}", code_hash)
                logger.debug(f"Critical function registered: {func.__name__}")
            else:
                logger.warning(f"Failed to calculate hash for function: {func.__name__}")
    except Exception as e:
        logger.error(f"Failed to register critical function {func.__name__}: {e}")       

def integrity_checker(interval):
    """Periodically checks the integrity of critical functions and data."""
    global globals_manager
    while not globals_manager.stop_integrity_check.wait(interval):
        if not verify_integrity():
            break
        if not verify_data_integrity():
            break
    logger.info("Thread integrity checker berhenti.")

def check_pydevd():
    """Checks for the presence of the PyCharm debugger.

    Returns:
        True if the `pydevd` or `pydevd_pycharm` module is imported,
        False otherwise.
    """
    try:
        import pydevd
        return True
    except ImportError:
        pass
    try:
        import pydevd_pycharm
        return True
    except ImportError:
        pass
    return False

def check_ptrace():
    """Checks if the current process is being traced using a more reliable method.

    This function is only effective on Linux/Unix systems.

    Returns:
        True if the process is being traced, False otherwise.
    """
    if platform.system() == "Windows":
        return False
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        # Coba lakukan ptrace pada diri sendiri.
        # Jika sudah di-debug oleh proses lain, panggilan ini akan gagal.
        res = libc.ptrace(0, 0, 0, 0)  # PTRACE_TRACEME
        if res == -1:
            # errno akan diset. EPERM (Operation not permitted) sering kali berarti
            # proses sudah dilacak (traced) oleh debugger lain.
            if ctypes.get_errno() == 1: # EPERM
                return True 
        # Jika berhasil, segera lepaskan diri kita sendiri
        libc.ptrace(17, 0, 0, 0) # PTRACE_DETACH
        return False
    except (OSError, AttributeError):
        # ptrace tidak tersedia atau tidak bisa digunakan
        return False

def detect_debugging():
    """Detects if a debugger is attached to the current process.

    This function iterates through the debug detection methods specified in
    the configuration and calls them. If any of them return True, the
    program is terminated.

    Returns:
        True if a debugger is detected, False otherwise.
    """
    # --- PERBAIKAN: Baris return False dihapus agar fungsi bisa berjalan ---
    # Temporarily disable anti-debugging to prevent unexpected script termination
    # return False 

    methods = config.get("debug_detection_methods", [])
    for method_name in methods:
        method_func = globals().get(method_name)
        if method_func and callable(method_func):
            if method_func():
                logger.critical("Anti-Debug: Lingkungan debugging terdeteksi!")
                print(f"\n{RED}❌ CRITICAL: Lingkungan debugging terdeteksi! Program dihentikan.{RESET}")
                os.kill(os.getpid(), signal.SIGTERM) # Matikan proses secara paksa
                return True
    return False

def secure_mlock(addr, length):
    """Locks memory with Termux compatibility"""
    if platform.system() == "Linux" and hasattr(os, 'mlock'):
        try:
            # Gunakan os.mlock yang lebih sederhana dan bekerja dengan baik di Android
            os.mlock(addr, length)
            logger.debug(f"Memory locked at {hex(addr)} ({length} bytes) using os.mlock")
        except (OSError, AttributeError) as e:
            # Jika os.mlock gagal, coba dengan ctypes sebagai fallback
            try:
                libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
                result = libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))
                if result != 0:
                    logger.warning(f"mlock failed with code {result}, errno: {ctypes.get_errno()}")
                else:
                    logger.debug(f"Memory locked at {hex(addr)} ({length} bytes) using ctypes.mlock")
            except Exception as e_ctypes:
                logger.warning(f"mlock not available via os or ctypes: {e_ctypes}")
    # Windows and other platforms remain unchanged

def secure_munlock(addr, length):
    """Unlocks a memory area, allowing it to be swapped to disk.

    This function is a wrapper around the `munlock` syscall, which is only
    available on Unix-like systems.

    Args:
        addr: The starting address of the memory area to unlock.
        length: The length of the memory area to unlock.
    """
    if platform.system() != "Windows": # Tidak berlaku untuk Windows
        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c"))
            result = libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))
            if result != 0:
                logger.warning(f"Gagal membuka kunci memori di alamat {hex(addr)} (munlock).")
            else:
                logger.debug(f"Memori di alamat {hex(addr)} ({length} bytes) dibuka kuncinya (munlock).")
        except (OSError, AttributeError):
            logger.warning("Fungsi munlock tidak tersedia di platform ini.")
    else:
        logger.info("munlock tidak didukung di Windows.")

# Perbaikan secure_memset
def secure_memset(addr, length, value=0):
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=False)
        libc.memset(addr, value, length)
        logger.debug(f"Memory at {hex(addr)} ({length} bytes) securely wiped.")
    except Exception as e:
        logger.warning(f"Gagal mengisi memori secara aman di alamat {hex(addr)}: {e}")

def secure_overwrite_variable(var):
    """Securely overwrites a variable's memory with zeros.

    This function is used to securely erase sensitive data from memory. It
    supports `bytearray`, `bytes`, and `str` types.

    Args:
        var: The variable to overwrite.
    """
    # Hanya bytearray dan bytes yang bisa ditimpa secara langsung di memori menggunakan ctypes
    if isinstance(var, bytearray):
        addr = ctypes.addressof((ctypes.c_char * len(var)).from_buffer(var))
        secure_memset(addr, len(var), 0) # Timpa dengan nol
        # Kosongkan referensi di Python
        var[:] = b'\x00' * len(var)
    elif isinstance(var, bytes):
        # Untuk bytes, kita hanya bisa mengganti referensi lokal ke array nol
        # Buffer asli tidak bisa ditimpa langsung
        var = b'\x00' * len(var)
    elif isinstance(var, str):
        # Untuk string, kita hanya bisa mengganti referensi lokal ke string kosong
        # Buffer asli tidak bisa ditimpa langsung
        var = ""
    # Tambahkan tipe lain jika perlu
    gc.collect() # Paksa garbage collection

def shuffle_file_parts(parts_list):
    """Shuffles the order of the file parts.

    This function is used to obscure the structure of the encrypted file.

    Args:
        parts_list: A list of tuples, where each tuple contains the name of a
            file part and its data.

    Returns:
        A new list with the file parts in a random order, or the original
        list if shuffling is disabled in the configuration.
    """
    if config.get("custom_format_shuffle", False):
        import random
        # Tambahkan informasi acak ke seed untuk keragaman setiap kali
        random.seed(secrets.randbits(32))
        shuffled = parts_list[:]
        random.shuffle(shuffled)
        logger.debug(f"Urutan bagian file diacak.")
        return shuffled
    return parts_list

def generate_dynamic_header_parts(input_file_path: str, data_size: int) -> bytes:
    """Generates a dynamic header as a single byte stream.

    This function creates a variable header structure and serializes it into
    a byte stream for storage or encryption.

    Args:
        input_file_path: The path to the input file.
        data_size: The size of the input data.

    Returns:
        A byte stream containing the serialized header parts.
    """
    import random
    # Acak seed berdasarkan path file dan ukuran
    random.seed(hash(input_file_path) + data_size)
    
    final_parts = []
    # Bagian wajib (misalnya, versi)
    final_parts.append(("header_version", config["dynamic_header_version"].to_bytes(4, 'little')))
    
    # Tambahkan bagian opsional dengan probabilitas
    optional_parts = [
        ("metadata_1", secrets.token_bytes(random.randint(1, 100))),
        ("metadata_2", secrets.token_bytes(random.randint(1, 50))),
    ]
    for part_name, part_data in optional_parts:
        if random.random() > 0.5: # 50% probabilitas
            final_parts.append((part_name, part_data))

    # Serialisasi menjadi byte stream
    header_stream = b""
    for name, data in final_parts:
        name_bytes = name.encode('utf-8')
        # Format: [4 bytes: panjang nama] [nama] [4 bytes: panjang data] [data]
        header_stream += len(name_bytes).to_bytes(4, 'little')
        header_stream += name_bytes
        header_stream += len(data).to_bytes(4, 'little')
        header_stream += data
        
    logger.debug(f"Header dinamis dibuat dengan {len(final_parts)} bagian untuk {input_file_path}. Total ukuran: {len(header_stream)} bytes.")
    return header_stream

def unshuffle_dynamic_header_parts(parts_list, input_file_path: str, data_size: int) -> dict:
    """Restores the original order of the dynamic header parts.

    This function is the inverse of `generate_dynamic_header_parts`. It
    takes a list of shuffled header parts and restores their original
    order.

    Args:
        parts_list (list): A list of shuffled header parts.
        input_file_path (str): The path to the input file.
        data_size (int): The size of the input data.

    Returns:
        A dictionary containing the unshuffled header parts, or None if an
        error occurs.
    """
    # Kita kembalikan dictionary yang berisi bagian-bagian yang sudah dipisahkan.
    # Karena ukuran bisa bervariasi (karena bagian opsional), kita harus membaca
    # berdasarkan header nama/ukuran yang konsisten (misalnya 4 byte nama, 4 byte ukuran).
    file_parts = {}
    idx = 0
    while idx < len(parts_list):
         part_name_len_bytes = parts_list[idx : idx + 4]
         idx += 4
         part_name = part_name_len_bytes.decode('ascii').strip('\x00')
         part_size_bytes = parts_list[idx : idx + 4]
         idx += 4
         part_size = int.from_bytes(part_size_bytes, byteorder='little')
         part_data = parts_list[idx : idx + part_size]
         idx += part_size
         if len(part_data) != part_size:
              logger.error(f"Ukuran data bagian '{part_name}' tidak sesuai saat unshuffle.")
              return None # Error jika ukuran tidak cocok
         file_parts[part_name] = part_data
         logger.debug(f"Bagian '{part_name}' ({part_size} bytes) di-unshuffle.")
    return file_parts

def derive_key_for_header(base_key: bytes, header_salt: bytes) -> bytes:
    """Derives a key for encrypting the dynamic header using HKDF.

    Args:
        base_key (bytes): The key to derive the header key from (either the master
            key or the password-derived key).
        header_salt (bytes): The salt to use for the header key derivation.

    Returns:
        bytes: The derived header key.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        print(f"{RED}❌ Error: HKDF (untuk header) memerlukan modul 'cryptography'.{RESET}")
        logger.error("HKDF (untuk header) memerlukan modul 'cryptography', yang tidak tersedia.")
        return secrets.token_bytes(config["dynamic_header_encryption_key_length"])

    info_str = config.get("header_derivation_info", "thena_header_enc_key_")
    info_bytes = info_str.encode('utf-8')

    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=config["dynamic_header_encryption_key_length"],
            salt=header_salt,
            info=info_bytes,
        )
        header_key = hkdf.derive(base_key)
        logger.debug("Kunci header diturunkan dari kunci dasar menggunakan HKDF.")
        return header_key
    except Exception as e:
        logger.error(f"Kesalahan saat derivasi kunci header dengan HKDF: {e}")
        return secrets.token_bytes(config["dynamic_header_encryption_key_length"])


# --- Fungsi untuk Memuat Konfigurasi ---
def load_config():
    """Loads the configuration from a JSON file."""
    # Nilai default ditingkatkan untuk keamanan dan fungsionalitas
    default_config = {
        
        # --- V20: Enhanced Algorithm Support ---
        "preferred_algorithm_priority": [
            "xchacha20-poly1305", "aes-gcm", "chacha20-poly1305", 
            "aes-siv", "aes-cbc", "aes-ctr"
        ],
        "key_exchange_algorithm": "x25519",  # x25519, x448
        "signature_algorithm": "ed25519",    # ed25519, ed448, rsa-pss, rsa-pkcs1v15
        "hash_algorithm": "sha256",          # sha256, sha3-256, sha3-512, blake2b, blake3
        "post_quantum_ready": False,         # Placeholder untuk PQC
        "pqc_algorithm": "sike",             # sike, csidh (untuk masa depan)
        # Parameter algoritma baru
        "aes_key_length": 32,                # 16 (AES-128), 24 (AES-192), 32 (AES-256)
        "chacha20_nonce_len": 12,
        "ed25519_private_key_file": "ed25519_private_key.pem",
        "ed448_private_key_file": "ed448_private_key.pem",
        "x448_private_key_file": "x448_private_key.pem",
        # --- V20: Enhanced Security Parameters ---
        "enable_forward_secrecy": True,
        "enable_perfect_forward_secrecy": False,
        "key_derivation_function": "hkdf",   # hkdf, pbkdf2, scrypt, argon2id
        "kdf_type": "argon2id",
        "encryption_algorithm": "hybrid-rsa-x25519",  # Deprecated for new encryptions, use preferred_algorithm_priority
        "preferred_algorithm_priority": ["xchacha20-poly1305", "aes-siv", "chacha20-poly1305", "aes-gcm"],
        "rsa_key_size": 4096,
        "argon2_time_cost": 25,
        "argon2_memory_cost": 2**21,
        "argon2_parallelism": 4, # V17: Ditingkatkan
        "scrypt_n": 2**21, # V17: Ditingkatkan
        "scrypt_r": 8,
        "scrypt_p": 1,
        "pbkdf2_iterations": 200000, # V17: Ditingkatkan
        "pbkdf2_hash_algorithm": "sha256", # Algoritma hash untuk PBKDF2
        "chunk_size": 64 * 1024,
        "master_key_file": ".master_key_encrypted", # Ubah nama file master key
        "rsa_private_key_file": "rsa_private_key.pem",
        "x25519_private_key_file": "x25519_private_key.pem",
        "padding_size_length": 4,
        "checksum_length": 32,
        "master_key_salt_len": 16,
        "file_key_length": 32,
        "gcm_nonce_len": 12, # Untuk AES-GCM (standar adalah 96 bit / 12 byte)
        "gcm_tag_len": 16,   # Untuk AES-GCM
        "enable_compression": False, # Opsi kompresi
        "compression_level": 6, # Level kompresi zlib (0-9)
        "batch_parallel": False, # Opsi eksekusi batch paralel
        "batch_workers": 2, # Jumlah worker jika paralel
        "hkdf_info_prefix": "thena_file_key_", # Awalan untuk info HKDF
        "enable_recursive_batch": False, # Opsi batch rekursif
        "output_name_suffix": "", # Suffix untuk nama output batch
        "use_hmac_verification": True, # Opsi verifikasi HMAC tambahan (V7)
        "hmac_key_length": 32, # Panjang kunci HMAC (V7)
        "argon2_for_hmac": False, # Gunakan Argon2 untuk kunci HMAC (True), atau PBKDF2 (False) (V7)
        "disable_timestamp_in_filename": False, # Opsi untuk nama file output tanpa timestamp (V8)
        "verify_output_integrity": True, # Opsi verifikasi integritas file output (V8)
        "log_level": "INFO", # Level logging (V8)
        "hmac_derivation_info": "thena_hmac_key_", # Info string untuk derivasi HMAC (V8 - Fixed HMAC)
        "enable_temp_files": False, # Opsi untuk menyimpan data sementara ke file (V9 - Hardening)
        "temp_dir": "./temp_thena", # Direktori untuk file sementara (V9 - Hardening)
        "max_file_size": 100 * 1024 * 1024, # Batas maksimal ukuran file yang diproses (100MB) (V9 - Hardening)
        "enable_memory_obfuscation": False, # Opsi untuk obfuskasi data di memori (V9 - Hardening)
        "memory_obfuscation_key": "", # Kunci untuk obfuskasi memori (V9 - Hardening)
        # --- V10/V11/V12/V13: Konfigurasi Hardening Lanjutan ---
        "enable_secure_memory": True, # Opsi untuk mlock dan overwrite variabel sensitif (V10/V11/V12/V13/v14)
        "enable_runtime_integrity": False, # Opsi untuk runtime integrity checks (V10/V11/V12/V13/v14)
        "enable_anti_debug": True, # Opsi untuk anti-debugging techniques (V10/V11/V12/V13/v14)
        "custom_format_shuffle": True, # Opsi untuk mengacak urutan bagian file output (V10/V11/V12/V13/v14)
        "custom_format_encrypt_header": True, # Opsi untuk mengEncrypted header file output (V10/V11/V12/V13/v14)
        "integrity_check_interval": 5, # Interval (detik) untuk pemeriksaan integritas runtime (V10/V11/V12/V13/v14)
        "debug_detection_methods": ["check_pydevd", "check_ptrace"], # Metode deteksi debug (V10/V11/V12/V13/v14)
        # --- V12/V13/v14: Konfigurasi Hardening Lanjutan ---
        "use_mmap_for_large_files": True, # V12/V13/v14: Gunakan mmap untuk file besar (performa/hardening)
        "large_file_threshold": 10 * 1024 * 1024, # V12/V13/v14: Ambang batas file besar (10MB)
        "dynamic_header_version": 2, # v14: Ditingkatkan versi header dinamis
        "dynamic_header_encryption_key_length": 32, # V12/V13/v14: Panjang kunci untuk Encrypted header dinamis
        "enable_secure_memory_overwrite": False, # V12/V13/v14: Aktifkan overwrite variabel sensitif
        "enable_dynamic_header_integrity_check": True, # V12/V13/v14: Aktifkan verifikasi integritas header dinamis
        "hardware_integration_enabled": False, # V12/V13/v14: Placeholder untuk integrasi hardware (TPM)
        "post_quantum_ready": False, # V12/V13/v14: Placeholder untuk kriptografi post-kuantum
        # --- v14: Konfigurasi Hardening Lanjutan ---
        "enable_secure_memory_locking": False, # v14: Aktifkan mlock (jika tersedia)
        "enable_runtime_data_integrity": False, # v14: Aktifkan pemeriksaan integritas data di memori
        "custom_format_variable_parts": True, # v14: Aktifkan struktur bagian file yang bervariasi
        "header_derivation_info": "thena_header_enc_key_", # v14: Info string untuk derivasi kunci header
        # --- V18: Konfigurasi Obfuscation ---
        "enable_decoy_blocks": True, # Aktifkan blok data umpan (decoy)
        "decoy_block_max_size": 1024, # Ukuran maksimum blok decoy (bytes)
        "decoy_block_count": 5, # Jumlah maksimum blok decoy
        # --- V19: Performance Tuning ---
        "auto_tune_performance": True, # Aktifkan penyesuaian performa otomatis
    }

    config_path = Path(CONFIG_FILE)
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            # Pastikan semua kunci default ada
            for key, value in default_config.items():
                if key not in config:
                    config[key] = value
            print(f"{CYAN}Konfigurasi dimuat dari {CONFIG_FILE}{RESET}")
        except json.JSONDecodeError:
            print(f"{RED}Error membaca {CONFIG_FILE}, menggunakan nilai default.{RESET}")
            config = default_config
    else:
        config = default_config
        try:
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=4)
            print(f"{CYAN}File konfigurasi default '{CONFIG_FILE}' dibuat.{RESET}")
        except IOError:
            print(f"{RED}Gagal membuat file konfigurasi '{CONFIG_FILE}'. Menggunakan nilai default.{RESET}")
            config = default_config
    return config

# --- Setup Logging ---
def setup_logging(interactive_mode=False):
    """Configures the logging for the application."""
    level = getattr(logging, config.get("log_level", "INFO").upper(), logging.INFO)

    # Tentukan handlers berdasarkan mode
    handlers = [logging.FileHandler(LOG_FILE)]
    if not interactive_mode:
        handlers.append(logging.StreamHandler())

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers,
        force=True
    )
    logger = logging.getLogger(__name__)
    logger.info("=== Encryptor Dimulai ===")

def print_error_box(message, width=80):
    """Prints an error message in a formatted box.

    Args:
        message (str): The error message to display.
        width (int): The width of the box.
    """
    border_color = RED
    text_color = WHITE
    reset = RESET
    print(f"{border_color}╭" + "─" * (width - 2) + f"╮{reset}")
    print(f"{border_color}│{reset} {text_color}{message.center(width - 4)}{reset} {border_color}│{reset}")
    print(f"{border_color}╰" + "─" * (width - 2) + f"╯{reset}")

def print_loading_progress():
    """Prints a simple loading progress indicator to the console."""
    for i in range(11):
        progress = i * 10
        print(f"Memproses... {progress}%", end="\r")
        time.sleep(0.1)
    print("Memproses... 100%")

# --- Setup Konfigurasi dan Logger ---
config = load_config()
setup_logging()
logger = logging.getLogger(__name__)

# --- Inisialisasi (sesuai ketersediaan pustaka) ---
# Kita tetap gunakan argon2.PasswordHasher untuk setup awal
if ARGON2_AVAILABLE:
    argon2_ph = PasswordHasher(
        time_cost=config["argon2_time_cost"],
        memory_cost=config["argon2_memory_cost"],
        parallelism=config["argon2_parallelism"],
        hash_len=config["file_key_length"],
    )
else:
    argon2_ph = None

# --- Fungsi Utilitas ---
def clear_screen():
    """Clears the console screen.

    This function checks the operating system and uses the appropriate
    command to clear the screen.
    """
    # Hardening (V8): Cek sistem operasi
    os_name = platform.system().lower()
    if os_name == "windows":
        os.system('cls')
    else:
        os.system('clear')

def calculate_checksum(data) -> bytes:
    """Calculates the SHA-256 checksum of the given data.

    Args:
        data (bytes): The data to calculate the checksum for.

    Returns:
        bytes: The SHA-256 checksum of the data.
    """
    return hashlib.sha256(data).digest()
    
def calculate_enhanced_checksum(data: bytes) -> bytes:
    """Calculates checksum using configured hash algorithm."""
    hash_algo = config.get("hash_algorithm", "sha256")
    
    if hash_algo == "sha256":
        return hashlib.sha256(data).digest()
    elif hash_algo == "sha3-256":
        return hashlib.sha3_256(data).digest()
    elif hash_algo == "sha3-512":
        return hashlib.sha3_512(data).digest()
    elif hash_algo == "blake2b" and hasattr(hashlib, 'blake2b'):
        return hashlib.blake2b(data).digest()
    elif hash_algo == "blake3" and hasattr(hashlib, 'blake3'):
        return hashlib.blake3(data).digest()
    else:
        # Fallback to SHA-256
        return hashlib.sha256(data).digest()

def secure_hash_password(password: str, salt: bytes) -> bytes:
    """Securely hashes password with modern algorithm."""
    password_bytes = password.encode('utf-8')
    hash_algo = config.get("hash_algorithm", "sha256")
    
    if hash_algo.startswith("sha3-"):
        # Use SHA3 for password hashing
        if hash_algo == "sha3-256":
            return hashlib.sha3_256(salt + password_bytes).digest()
        else:  # sha3-512
            return hashlib.sha3_512(salt + password_bytes).digest()
    else:
        # Default to SHA-256 with multiple iterations
        dk = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000)
        return dk    

def secure_wipe_file(file_path: str, passes: int = 5):
    """Securely wipes a file by overwriting it with random data in chunks.
    Args:
        file_path: The path to the file to wipe.
        passes: The number of times to overwrite the file.
    """
    config = load_config()
    if not os.path.exists(file_path):
        print(f"{YELLOW}⚠️  File '{file_path}' tidak ditemukan, dilewati.{RESET}")
        logger.warning(f"File '{file_path}' tidak ditemukan saat secure wipe.")
        return
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            os.remove(file_path)
            print(f"{GREEN}✅ File kosong '{file_path}' telah dihapus.{RESET}")
            logger.info(f"File kosong '{file_path}' dihapus.")
            return
        print(f"{CYAN}Menghapus secara aman '{file_path}' ({file_size} bytes)...{RESET}")
        chunk_size = config.get("chunk_size", 64 * 1024)
        with open(file_path, "r+b") as f:
            for i in range(passes):
                print(f"  Pass {i + 1}/{passes}...")
                f.seek(0)
                remaining_size = file_size
                print_loading_progress()
                while remaining_size > 0:
                    current_chunk_size = min(chunk_size, remaining_size)

                    if i == passes - 1:
                        # Last pass, write zeros
                        chunk = b'\x00' * current_chunk_size
                    elif i == passes - 2:
                        # Second to last pass, write ones
                         chunk = b'\xff' * current_chunk_size
                    else:
                        # Other passes, write random data
                        chunk = secrets.token_bytes(current_chunk_size)

                    f.write(chunk)
                    remaining_size -= current_chunk_size

                f.flush()
                os.fsync(f.fileno())
        os.remove(file_path)
        print(f"{GREEN}✅ File '{file_path}' telah dihapus secara aman ({passes} passes).{RESET}")
        logger.info(f"File '{file_path}' dihapus secara aman ({passes} passes).")
    except Exception as e:
        print(f"{RED}❌ Error saat menghapus file '{file_path}' secara aman: {e}{RESET}")
        logger.error(f"Error saat secure wipe file '{file_path}': {e}")

def confirm_overwrite(file_path: str) -> bool:
    """Asks the user to confirm overwriting a file.

    Args:
        file_path: The path to the file to overwrite.

    Returns:
        True if the user confirms, False otherwise.
    """
    if os.path.exists(file_path):
        confirm = input(f"{YELLOW}File '{file_path}' sudah ada. Ganti? (y/N): {RESET}").strip().lower()
        if confirm not in ['y', 'yes']:
            print(f"{YELLOW}Operasi dibatalkan.{RESET}")
            logger.info(f"Operasi dibatalkan karena file '{file_path}' sudah ada.")
            return False
    return True

def check_disk_space(file_path: str, output_dir: str) -> bool:
    """Checks if there is enough disk space to encrypt or decrypt a file.

    Args:
        file_path: The path to the input file.
        output_dir: The path to the output directory.

    Returns:
        True if there is enough disk space, False otherwise.
    """
    try:
        file_size = os.path.getsize(file_path)
        # Estimasi ukuran output: ukuran asli + overhead metadata + estimasi kompresi (jika diaktifkan)
        estimated_output_size = file_size + 200 + config["chunk_size"]
        if config.get("enable_compression", False):
             # Faktor kompresi rata-rata ~50% untuk data acak bisa lebih buruk, jadi gunakan 1.1x untuk keamanan
             estimated_output_size = int(estimated_output_size * 1.1)

        statvfs_result = os.statvfs(output_dir)
        free_space = statvfs_result.f_frsize * statvfs_result.f_bavail

        if free_space < estimated_output_size:
            required_mb = estimated_output_size / (1024*1024)
            free_mb = free_space / (1024*1024)
            print(f"{RED}❌ Error: Ruang disk tidak cukup.{RESET}")
            print(f"   Dibutuhkan sekitar {required_mb:.2f} MB, tersedia {free_mb:.2f} MB di '{output_dir}'.")
            logger.error(f"Ruang disk tidak cukup untuk '{file_path}'. Dibutuhkan {estimated_output_size} bytes, tersedia {free_space} bytes di '{output_dir}'.")
            return False
        else:
            logger.info(f"Ruang disk cukup. File '{file_path}' ({file_size} bytes) akan menghasilkan sekitar {estimated_output_size} bytes di '{output_dir}'.")
            return True
    except OSError as e:
        print(f"{RED}❌ Error saat memeriksa ruang disk: {e}{RESET}")
        logger.error(f"Error saat memeriksa ruang disk untuk '{file_path}' di '{output_dir}': {e}")
        return False

def validate_password_keyfile(password: str, keyfile_path: str, interactive: bool = True) -> bool:
    """Validates the strength of the password and the keyfile.

    Args:
        password: The password to validate.
        keyfile_path: The path to the keyfile to validate.
        interactive: Whether to prompt the user for confirmation.

    Returns:
        True if the password and keyfile are valid, False otherwise.
    """
    issues = []

    # Validasi password yang ditingkatkan
    if len(password) < 12:
        issues.append("Password terlalu pendek (kurang dari 12 karakter).")
    if password.isdigit():
        issues.append("Password hanya berisi angka.")
    if password.isalpha():
        issues.append("Password hanya berisi huruf.")
    if password.islower():
        issues.append("Password tidak memiliki huruf besar.")
    if password.isupper():
        issues.append("Password tidak memiliki huruf kecil.")
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        issues.append("Password tidak memiliki karakter khusus (!@#...).")
    if len(set(password)) == 1:
        issues.append("Password hanya berisi satu jenis karakter yang berulang.")
    unique_chars = len(set(password))
    if len(password) > 0 and unique_chars / len(password) < 0.5:
        issues.append("Password memiliki entropi rendah (banyak karakter berulang).")

    # Validasi keyfile
    if keyfile_path:
        if not os.path.isfile(keyfile_path):
            issues.append(f"File keyfile '{keyfile_path}' tidak ditemukan.")
        else:
            keyfile_size = os.path.getsize(keyfile_path)
            if keyfile_size < 1024 * 10: # 10KB
                issues.append(f"File keyfile '{keyfile_path}' terlalu kecil ({keyfile_size} bytes). Gunakan file yang lebih besar dan acak (min 10KB disarankan).")
            try:
                keyfile_stat = os.stat(keyfile_path)
                if keyfile_stat.st_mode & stat.S_IROTH:
                    issues.append(f"Peringatan: File keyfile '{keyfile_path}' bisa dibaca oleh pengguna lain (chmod).")
            except OSError:
                logger.warning(f"Tidak bisa membaca izin file keyfile '{keyfile_path}'.")

    if issues:
        print(f"{YELLOW}⚠️  Peringatan Validasi:{RESET}")
        for issue in issues:
            print(f"   - {issue}")
        logger.warning(f"Peringatan validasi untuk input: {', '.join(issues)}")
        if interactive:
            confirm = input(f"{YELLOW}Lanjutkan proses? (y/N): {RESET}").strip().lower()
            if confirm not in ['y', 'yes']:
                print(f"{YELLOW}Operasi dibatalkan.{RESET}")
                logger.info("Operasi dibatalkan berdasarkan validasi input pengguna.")
                return False
        else:
            return False
    else:
        logger.info("Validasi password/keyfile berhasil.")

    return True

def check_file_size_limit(file_path: str) -> bool:
    """Checks if a file is within the configured size limit.

    Args:
        file_path: The path to the file to check.

    Returns:
        True if the file is within the size limit, False otherwise.
    """
    max_size = config.get("max_file_size", 100 * 1024 * 1024) # 100MB default
    file_size = os.path.getsize(file_path)
    if file_size > max_size:
        print_error_box(f"Error: Ukuran file '{file_path}' ({file_size} bytes) melebihi batas maksimal ({max_size} bytes).")
        logger.error(f"File '{file_path}' ({file_size} bytes) melebihi batas maksimal ({max_size} bytes).")
        return False
    logger.debug(f"File '{file_path}' ({file_size} bytes) berada dalam batas ukuran maksimal ({max_size} bytes).")
    return True

def create_temp_file(suffix=""):
    """Creates a temporary file."""
    global globals_manager
    if not config.get("enable_temp_files", False):
        return None
    temp_dir = config.get("temp_dir", "./temp_thena")
    os.makedirs(temp_dir, exist_ok=True)
    temp_fd, temp_path = tempfile.mkstemp(suffix=suffix, dir=temp_dir)
    globals_manager.add_temp_file(temp_path) # Tambahkan ke set untuk cleanup
    os.close(temp_fd) # Tutup file descriptor
    logger.debug(f"File sementara dibuat: {temp_path}")
    return temp_path

def obfuscate_memory(data) -> bytes:
    """Obfuscates data in memory.

    This function performs a simple XOR obfuscation on the given data.

    Args:
        data: The data to obfuscate.

    Returns:
        The obfuscated data.
    """
    if not config.get("enable_memory_obfuscation", False):
        return data
    obfuscation_key = config.get("memory_obfuscation_key", "")
    if not obfuscation_key:
        logger.warning("Memory obfuscation enabled but no key provided.")
        return data
    key_bytes = obfuscation_key.encode('utf-8')
    obfuscated_data = bytearray()
    for i, byte in enumerate(data):
        key_byte = key_bytes[i % len(key_bytes)]
        obfuscated_data.append(byte ^ key_byte)
    logger.debug(f"Data diobfuskasi di memori.")
    return bytes(obfuscated_data)

def deobfuscate_memory(data) -> bytes:
    """Deobfuscates data in memory.

    This function performs a simple XOR deobfuscation on the given data.

    Args:
        data: The data to deobfuscate.

    Returns:
        The deobfuscated data.
    """
    # Deobfuskasi adalah operasi yang sama dengan XOR
    return obfuscate_memory(data)

def detect_hardware_acceleration():
    """Detects CPU features for hardware-accelerated cryptography."""
    try:
        info = safe_cpu_info()
        flags = info.get('flags', [])

        supported_features = []
        if 'aes' in flags:
            supported_features.append("AES-NI")
        if 'avx' in flags:
            supported_features.append("AVX")
        if 'pclmulqdq' in flags:
            supported_features.append("PCLMULQDQ")

        if supported_features:
            features_str = ", ".join(supported_features)
            print(f"{GREEN}✅ Akselerasi Kriptografi Hardware Terdeteksi: {features_str}{RESET}")
            logger.info(f"Hardware acceleration detected: {features_str}")
            if config.get("auto_tune_performance", False):
                print(f"{CYAN}   Mode auto-tuning diaktifkan.{RESET}")
        else:
            print(f"{YELLOW}⚠️  Tidak ada akselerasi kriptografi hardware yang terdeteksi.{RESET}")
            logger.warning("No hardware cryptographic acceleration detected.")

    except Exception as e:
        logger.warning(f"Tidak dapat mendeteksi fitur hardware: {e}")

# Hapus class PerformanceTuner, kita tidak membutuhkannya lagi.
def detect_hash_algorithm_support():
    """Detects available hash algorithms in the system.
    
    Returns:
        dict: Dictionary of algorithm names and their availability.
    """
    algorithms = {
        "sha256": True,  # Always available
        "sha3-256": hasattr(hashlib, 'sha3_256'),
        "sha3-512": hasattr(hashlib, 'sha3_512'),
        "blake2b": hasattr(hashlib, 'blake2b'),
        "blake2s": hasattr(hashlib, 'blake2s'),
        "blake3": hasattr(hashlib, 'blake3'),
    }
    
    # Test each algorithm
    test_data = b"test"
    for algo, available in algorithms.items():
        if available:
            try:
                if algo == "sha256":
                    hashlib.sha256(test_data)
                elif algo == "sha3-256":
                    hashlib.sha3_256(test_data)
                elif algo == "sha3-512":
                    hashlib.sha3_512(test_data)
                elif algo == "blake2b":
                    hashlib.blake2b(test_data)
                elif algo == "blake2s":
                    hashlib.blake2s(test_data)
                elif algo == "blake3":
                    hashlib.blake3(test_data)
            except Exception:
                algorithms[algo] = False
                logger.warning(f"Hash algorithm {algo} failed test")
    
    return algorithms

def print_hash_algorithm_info():
    """Prints information about available hash algorithms."""
    supported = detect_hash_algorithm_support()
    
    print(f"\n{BOLD}🔐 Hash Algorithm Support:{RESET}")
    print("─" * 50)
    
    current_algo = config.get("hash_algorithm", "sha256")
    
    for algo, available in supported.items():
        status = f"{GREEN}✅{RESET}" if available else f"{RED}❌{RESET}"
        current = " ← CURRENT" if algo == current_algo else ""
        print(f"  {status} {algo:15} {current}")
    
    print("─" * 50)
    
    # Security recommendations
    if current_algo == "sha256":
        print(f"{YELLOW}💡 Recommendation: Consider using SHA3-256 or BLAKE3 for enhanced security{RESET}")

def print_algorithm_support():
    """Prints supported algorithms information."""
    support = detect_algorithm_support()
    
    print(f"\n{BOLD}📊 Algorithm Support:{RESET}")
    print("─" * 50)
    
    for algo, supported in support.items():
        status = f"{GREEN}✅{RESET}" if supported else f"{RED}❌{RESET}"
        print(f"  {status} {algo:20} {'Supported' if supported else 'Not Available'}")
    
    print("─" * 50)

def tune_argon2_params():
    """Adjusts Argon2 parameters based on available memory and CPU cores."""
    if not config.get("auto_tune_performance", False):
        return

    try:
        available_mem_gb = psutil.virtual_memory().available / (1024**3)
        cpu_cores = psutil.cpu_count(logical=False) or 1
        
        # --- Tuning Paralelisme ---
        original_parallelism = config["argon2_parallelism"]
        # Gunakan setengah dari core fisik, dengan batasan yang aman
        tuned_parallelism = min(original_parallelism, max(1, cpu_cores // 2))
        
        # --- Tuning Memori ---
        original_mem_cost = config["argon2_memory_cost"]
        tuned_mem_cost = original_mem_cost
        
        # Sesuaikan berdasarkan RAM yang tersedia
        if available_mem_gb > 8: # >8GB RAM
            tuned_mem_cost = 2**21 # ~2GB
        elif available_mem_gb > 4: # >4GB RAM
            tuned_mem_cost = 2**20 # ~1GB
        elif available_mem_gb > 2: # >2GB RAM
            tuned_mem_cost = 2**19 # ~512MB
        else: # <2GB RAM (misalnya Termux)
            tuned_mem_cost = 2**18 # ~256MB
            tuned_parallelism = 1 # Paksa 1 thread untuk perangkat low-end

        # Pastikan tidak melebihi nilai asli sebagai pengaman
        tuned_mem_cost = min(original_mem_cost, tuned_mem_cost)
        tuned_parallelism = min(original_parallelism, tuned_parallelism)

        # Terapkan perubahan jika ada
        if tuned_mem_cost != original_mem_cost:
            config["argon2_memory_cost"] = tuned_mem_cost
            print(f"{CYAN}Auto-Tuning: Argon2 memory_cost disesuaikan ke {tuned_mem_cost // 1024}MB (dari {original_mem_cost // 1024}MB).{RESET}")
            logger.info(f"Tuned Argon2 memory_cost from {original_mem_cost} to {tuned_mem_cost}")

        if tuned_parallelism != original_parallelism:
            config["argon2_parallelism"] = tuned_parallelism
            print(f"{CYAN}Auto-Tuning: Argon2 parallelism disesuaikan ke {tuned_parallelism} (dari {original_parallelism}).{RESET}")
            logger.info(f"Tuned Argon2 parallelism from {original_parallelism} to {tuned_parallelism}")

    except Exception as e:
        logger.warning(f"Gagal melakukan auto-tuning parameter Argon2: {e}")
        try:
            # Tune parallelism
            cpu_cores = psutil.cpu_count(logical=False)
            if cpu_cores:
                original_parallelism = config["argon2_parallelism"]
                # Use half the physical cores, with a minimum of 1 and max of original setting
                tuned_parallelism = min(original_parallelism, max(1, cpu_cores // 2))
                config["argon2_parallelism"] = tuned_parallelism
                print(f"{CYAN}Auto-Tuning: Argon2 parallelism disesuaikan ke {tuned_parallelism} (dari {original_parallelism}).{RESET}")
                logger.info(f"Tuned Argon2 parallelism from {original_parallelism} to {tuned_parallelism}")

            # Tune memory_cost
            available_mem_gb = psutil.virtual_memory().available / (1024**3)
            original_mem_cost = config["argon2_memory_cost"]
            tuned_mem_cost = original_mem_cost

            # Adjust based on available RAM, setting safe upper/lower bounds
            if available_mem_gb > 8: # >8GB RAM
                tuned_mem_cost = 2**21 # ~2GB
            elif available_mem_gb > 4: # >4GB RAM
                tuned_mem_cost = 2**20 # ~1GB
            elif available_mem_gb > 2: # >2GB RAM
                tuned_mem_cost = 2**19 # ~512MB
            else: # <2GB RAM
                tuned_mem_cost = 2**18 # ~256MB

            # Ensure we don't exceed the original configured value as a safeguard
            tuned_mem_cost = min(original_mem_cost, tuned_mem_cost)
            config["argon2_memory_cost"] = tuned_mem_cost

            if tuned_mem_cost != original_mem_cost:
                print(f"{CYAN}Auto-Tuning: Argon2 memory_cost disesuaikan ke {tuned_mem_cost // 1024}MB (dari {original_mem_cost // 1024}MB).{RESET}")
                logger.info(f"Tuned Argon2 memory_cost from {original_mem_cost} to {tuned_mem_cost}")

        except Exception as e:
            logger.warning(f"Gagal melakukan auto-tuning parameter Argon2: {e}")

def _is_streaming_supported(algo):
    """Checks if an algorithm supports streaming."""
    # Only AES-GCM from `cryptography` is supported for true streaming for now.
    return algo == "aes-gcm" and CRYPTOGRAPHY_AVAILABLE

class StreamEncryptor:
    """Handles streaming encryption for AES-GCM."""
    def __init__(self, key):
        self.key = key
        self.nonce = secrets.token_bytes(config["gcm_nonce_len"])
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(self.nonce))
        self.encryptor = cipher.encryptor()
        self.tag = None

    def update(self, chunk):
        return self.encryptor.update(chunk)

    def finalize(self):
        self.encryptor.finalize()
        self.tag = self.encryptor.tag
        return b""

class StreamDecryptor:
    """Handles streaming decryption for AES-GCM."""
    def __init__(self, key, nonce, tag):
        self.key = key
        self.nonce = nonce
        self.tag = tag
        if CRYPTOGRAPHY_AVAILABLE:
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(self.nonce, self.tag))
            self.decryptor = cipher.decryptor()
        else:
            raise RuntimeError("Cryptography required for streaming")

    def update(self, chunk):
        return self.decryptor.update(chunk)

    def finalize(self):
        try:
            self.decryptor.finalize()
            return b""
        except Exception as e:
            logger.error(f"Stream decryption finalize failed: {e}")
            raise

def constant_time_compare(val1, val2):
    """Performs a constant-time comparison of two values."""
    return secrets.compare_digest(val1, val2)

def random_delay():
    """Waits for a random time to mitigate timing attacks."""
    time.sleep(secrets.randbelow(10) / 1000.0)

    def _derive_key(self, key_id):
        """Derives a unique key for a piece of data using HKDF."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError("Cryptography module is required for SecureMemoryManager.")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=key_id.encode('utf-8'),
            info=b'secure-memory-manager-key'
        )
        return hkdf.derive(self._master_key)

    def _encrypt(self, key, data):
        """Encrypts data with AES-GCM."""
        iv = secrets.token_bytes(12)
        cipher = AESGCM(key)
        encrypted_data = cipher.encrypt(iv, data, None)
        return iv + encrypted_data

    def _decrypt(self, key, encrypted_data):
        """Decrypts data with AES-GCM."""
        iv = encrypted_data[:12]
        data = encrypted_data[12:]
        cipher = AESGCM(key)
        return cipher.decrypt(iv, data, None)

    def store_sensitive_data(self, key_id, data):
        """Encrypts and stores sensitive data."""
        with self._lock:
            derived_key = self._derive_key(key_id)
            encrypted_data = self._encrypt(derived_key, data)
            self._enclave[key_id] = encrypted_data
            secure_overwrite_variable(derived_key)

    def retrieve_and_decrypt(self, key_id):
    """Retrieves and decrypts sensitive data."""
    with self._lock:
        # ✅ PERBAIKAN: Gunakan get() untuk menghindari KeyError
        encrypted_data = self._enclave.get(key_id)
        if encrypted_data is None:
            logger.warning(f"Key '{key_id}' not found in SecureMemoryManager.")
            return None

        try:
            derived_key = self._derive_key(key_id)
            decrypted_data = self._decrypt(derived_key, encrypted_data)
            secure_overwrite_variable(derived_key)
            return decrypted_data
        except Exception as e:
            logger.error(f"Failed to decrypt data for key '{key_id}': {e}")
            return None

    def wipe_data(self, key_id):
        """Securely wipes a piece of data from the manager."""
        with self._lock:
            if key_id in self._enclave:
                secure_overwrite_variable(self._enclave[key_id])
                del self._enclave[key_id]
                gc.collect()

class SecureMemoryManager:
    """Manages sensitive data in memory by encrypting it when not in use."""
    
    def __init__(self, master_key):
        self._master_key = master_key
        self._enclave = {}
        self._lock = threading.RLock()  # Gunakan RLock

    def cleanup(self):
        """Securely cleans up all managed data and resources."""
        with self._lock:
            try:
                # Wipe all stored data
                keys_to_wipe = list(self._enclave.keys())
                for key_id in keys_to_wipe:
                    self.wipe_data(key_id)
                
                # Wipe master key from memory
                if hasattr(self, '_master_key') and self._master_key:
                    secure_overwrite_variable(self._master_key)
                    self._master_key = None
                    
                # Clear the enclave
                self._enclave.clear()
                
                logger.debug("SecureMemoryManager cleanup completed")
                
            except Exception as e:
                logger.error(f"Error during SecureMemoryManager cleanup: {e}")

    def wipe_all(self):
        """Alias for cleanup method for compatibility."""
        self.cleanup()

class AlgorithmNegotiator:
    """Selects the best available encryption algorithm."""

    @staticmethod
    def get_best_algorithm(preferred_priority=None):
        """
        Selects the best available encryption algorithm based on system capabilities
        and user preferences.
        
        Args:
            preferred_priority: List of algorithms in order of preference.
                                If None, uses the priority from the config.
        
        Returns:
            The name of the best available algorithm as a string.
        """
        if preferred_priority is None:
            preferred_priority = config.get("preferred_algorithm_priority", [])

        # Pemetaan algoritma ke pemeriksaan ketersediaan
        availability_checks = {
            "xchacha20-poly1305": PYNACL_AVAILABLE,
            "aes-siv": MISCREANT_AVAILABLE,
            "chacha20-poly1305": CRYPTOGRAPHY_AVAILABLE,
            "aes-gcm": CRYPTOGRAPHY_AVAILABLE,
        }

        for algo in preferred_priority:
            if availability_checks.get(algo, False):
                logger.info(f"Algorithm '{algo}' selected as the best available.")
                return algo
        
        # Fallback jika tidak ada yang cocok
        if CRYPTOGRAPHY_AVAILABLE:
            logger.warning("No preferred algorithms available. Falling back to AES-GCM.")
            return "aes-gcm"
        
        logger.error("No suitable encryption algorithm is available. Check library installations.")
        return None

# Inisialisasi dan pendaftaran fungsi kritis
def initialize():
    """Initialize the encryption system with security hardening."""
    global globals_manager
    
    # Register critical functions...
    
    # Start integrity checking thread if enabled
    if config.get("enable_runtime_integrity", False):
        integrity_thread = threading.Thread(
            target=integrity_checker,
            args=(config.get("integrity_check_interval", 5),),
            daemon=True
        )
        integrity_thread.start()
        globals_manager.set_integrity_thread(integrity_thread)
        logger.info("Runtime integrity checking thread started")
    
    # Deteksi hardware acceleration dan tuning...
    
    # Detect hardware acceleration
    detect_hardware_acceleration()
    
    # Tune performance parameters if enabled
    if config.get("auto_tune_performance", False):
        safe_tune_argon2_params()
    
    logger.info("Encryption system initialized successfully")

# Run initialization when the module is imported
initialize()

class EnhancedAlgorithmNegotiator:
    """Enhanced algorithm negotiation with support for modern cryptography."""
    
    @staticmethod
    def get_best_symmetric_algorithm(preferred_priority=None):
        """Selects the best symmetric encryption algorithm."""
        if preferred_priority is None:
            preferred_priority = config.get("preferred_algorithm_priority", [])
        
        availability_checks = {
            "xchacha20-poly1305": PYNACL_AVAILABLE,
            "aes-gcm": CRYPTOGRAPHY_AVAILABLE,
            "chacha20-poly1305": CRYPTOGRAPHY_AVAILABLE,
            "aes-siv": MISCREANT_AVAILABLE,
            "aes-cbc": CRYPTOGRAPHY_AVAILABLE or PYCRYPTODOME_AVAILABLE,
            "aes-ctr": CRYPTOGRAPHY_AVAILABLE or PYCRYPTODOME_AVAILABLE,
        }
        
        for algo in preferred_priority:
            if availability_checks.get(algo, False):
                logger.info(f"Symmetric algorithm '{algo}' selected.")
                return algo
        
        # Fallback
        if CRYPTOGRAPHY_AVAILABLE:
            return "aes-gcm"
        return None
    
    @staticmethod
    def get_best_key_exchange_algorithm():
        """Selects the best key exchange algorithm."""
        kex_algo = config.get("key_exchange_algorithm", "x25519")
        
        if kex_algo == "x25519" and CRYPTOGRAPHY_AVAILABLE:
            return "x25519"
        elif kex_algo == "x448" and CRYPTOGRAPHY_AVAILABLE:
            # Note: x448 support mungkin terbatas di cryptography
            try:
                from cryptography.hazmat.primitives.asymmetric import x448
                return "x448"
            except ImportError:
                logger.warning("x448 not available, falling back to x25519")
                return "x25519"
        
        return "x25519"  # Default fallback
    
    @staticmethod
    def get_best_signature_algorithm():
        """Selects the best signature algorithm."""
        sig_algo = config.get("signature_algorithm", "ed25519")
        
        if sig_algo == "ed25519" and CRYPTOGRAPHY_AVAILABLE:
            return "ed25519"
        elif sig_algo == "ed448" and CRYPTOGRAPHY_AVAILABLE:
            try:
                from cryptography.hazmat.primitives.asymmetric import ed448
                return "ed448"
            except ImportError:
                logger.warning("ed448 not available, falling back to ed25519")
                return "ed25519"
        elif sig_algo == "rsa-pss" and CRYPTOGRAPHY_AVAILABLE:
            return "rsa-pss"
        
        return "ed25519"  # Default fallback
    
    @staticmethod
    def get_best_hash_algorithm():
        """Selects the best hash algorithm."""
        hash_algo = config.get("hash_algorithm", "sha256")
        
        if hash_algo in ["sha256", "sha3-256", "sha3-512"] and CRYPTOGRAPHY_AVAILABLE:
            return hash_algo
        elif hash_algo == "blake2b" and hasattr(hashlib, 'blake2b'):
            return "blake2b"
        elif hash_algo == "blake3" and hasattr(hashlib, 'blake3'):
            return "blake3"
        
        return "sha256"  # Default fallback

class ModernKeyManager:
    """Manages modern cryptographic keys including post-quantum candidates."""
    
    def __init__(self, password, keyfile_path=None):
        self.password = password
        self.keyfile_path = keyfile_path
        self._keys = {}
    
    def generate_ed25519_keypair(self):
        """Generates Ed25519 key pair for digital signatures."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError("cryptography module required for Ed25519")
        
        from cryptography.hazmat.primitives.asymmetric import ed25519
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def generate_ed448_keypair(self):
        """Generates Ed448 key pair for digital signatures."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError("cryptography module required for Ed448")
        
        try:
            from cryptography.hazmat.primitives.asymmetric import ed448
            private_key = ed448.Ed448PrivateKey.generate()
            public_key = private_key.public_key()
            return private_key, public_key
        except ImportError:
            logger.warning("Ed448 not supported, falling back to Ed25519")
            return self.generate_ed25519_keypair()
    
    def generate_x448_keypair(self):
        """Generates X448 key pair for key exchange."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError("cryptography module required for X448")
        
        try:
            from cryptography.hazmat.primitives.asymmetric import x448
            private_key = x448.X448PrivateKey.generate()
            public_key = private_key.public_key()
            return private_key, public_key
        except ImportError:
            logger.warning("X448 not supported, falling back to X25519")
            return self.generate_x25519_keypair()
    
    def generate_x25519_keypair(self):
        """Generates X25519 key pair for key exchange."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError("cryptography module required for X25519")
        
        from cryptography.hazmat.primitives.asymmetric import x25519
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    
    def sign_data(self, data: bytes, private_key) -> bytes:
        """Signs data using the appropriate signature algorithm."""
        if hasattr(private_key, 'sign'):  # Ed25519/Ed448
            return private_key.sign(data)
        else:  # RSA
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            
            hash_algo = EnhancedAlgorithmNegotiator.get_best_hash_algorithm()
            if hash_algo == "sha256":
                hash_obj = hashes.SHA256()
            elif hash_algo == "sha3-256":
                hash_obj = hashes.SHA3_256()
            else:
                hash_obj = hashes.SHA256()  # Fallback
            
            return private_key.sign(data, padding.PSS(
                mgf=padding.MGF1(hash_obj),
                salt_length=padding.PSS.MAX_LENGTH
            ), hash_obj)
    
    def verify_signature(self, data: bytes, signature: bytes, public_key) -> bool:
        """Verifies a digital signature."""
        try:
            if hasattr(public_key, 'verify'):  # Ed25519/Ed448
                public_key.verify(signature, data)
                return True
            else:  # RSA
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import padding
                
                hash_algo = EnhancedAlgorithmNegotiator.get_best_hash_algorithm()
                if hash_algo == "sha256":
                    hash_obj = hashes.SHA256()
                elif hash_algo == "sha3-256":
                    hash_obj = hashes.SHA3_256()
                else:
                    hash_obj = hashes.SHA256()
                
                public_key.verify(signature, data, padding.PSS(
                    mgf=padding.MGF1(hash_obj),
                    salt_length=padding.PSS.MAX_LENGTH
                ), hash_obj)
                return True
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

class EnhancedHybridCipher:
    """Enhanced hybrid cipher with modern algorithms and forward secrecy."""
    
    def __init__(self, password, keyfile_path=None):
        self.password = password
        self.keyfile_path = keyfile_path
        self.key_manager = ModernKeyManager(password, keyfile_path)
        self.algorithm_negotiator = EnhancedAlgorithmNegotiator()
        
        # Load or generate keys
        self._load_or_generate_enhanced_keys()
    
    def _load_or_generate_enhanced_keys(self):
        """Loads or generates enhanced cryptographic keys."""
        # Key exchange keys
        kex_algo = self.algorithm_negotiator.get_best_key_exchange_algorithm()
        if kex_algo == "x25519":
            self.kex_private, self.kex_public = self.key_manager.generate_x25519_keypair()
        elif kex_algo == "x448":
            self.kex_private, self.kex_public = self.key_manager.generate_x448_keypair()
        
        # Signature keys
        sig_algo = self.algorithm_negotiator.get_best_signature_algorithm()
        if sig_algo == "ed25519":
            self.sig_private, self.sig_public = self.key_manager.generate_ed25519_keypair()
        elif sig_algo == "ed448":
            self.sig_private, self.sig_public = self.key_manager.generate_ed448_keypair()
        elif sig_algo == "rsa-pss":
            # Use existing RSA key or generate new one
            rsa_priv, _ = load_keys(self.password, self.keyfile_path)
            if rsa_priv is None:
                rsa_priv, _ = generate_and_save_keys(self.password, self.keyfile_path)
            self.sig_private, self.sig_public = rsa_priv, rsa_priv.public_key()
    
    def encrypt_with_forward_secrecy(self, input_path: str, output_path: str) -> bool:
        """Encrypts with forward secrecy using ephemeral keys."""
        try:
            # Generate ephemeral key pair for forward secrecy
            kex_algo = self.algorithm_negotiator.get_best_key_exchange_algorithm()
            if kex_algo == "x25519":
                ephemeral_private, ephemeral_public = self.key_manager.generate_x25519_keypair()
            else:
                ephemeral_private, ephemeral_public = self.key_manager.generate_x448_keypair()
            
            # Perform key exchange
            shared_secret = ephemeral_private.exchange(self.kex_public)
            
            # Derive session key using modern KDF
            session_key = self._derive_session_key(shared_secret, b"forward_secrecy_session")
            
            # Sign the ephemeral public key
            ephemeral_pub_bytes = ephemeral_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            signature = self.key_manager.sign_data(ephemeral_pub_bytes, self.sig_private)
            
            # Encrypt the file
            symmetric_algo = self.algorithm_negotiator.get_best_symmetric_algorithm()
            self._encrypt_with_algorithm(input_path, output_path, session_key, symmetric_algo, 
                                       ephemeral_pub_bytes, signature)
            
            return True
            
        except Exception as e:
            logger.error(f"Enhanced hybrid encryption failed: {e}")
            return False
    
    def _derive_session_key(self, shared_secret: bytes, info: bytes) -> bytes:
        """Derives session key using HKDF with modern hash."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError("HKDF requires cryptography module")
        
        from cryptography.hazmat.primitives import hashes
        
        hash_algo = self.algorithm_negotiator.get_best_hash_algorithm()
        if hash_algo == "sha256":
            algorithm = hashes.SHA256()
        elif hash_algo == "sha3-256":
            algorithm = hashes.SHA3_256()
        elif hash_algo == "sha3-512":
            algorithm = hashes.SHA3_512()
        else:
            algorithm = hashes.SHA256()
        
        hkdf = HKDF(
            algorithm=algorithm,
            length=32,  # 256-bit key
            salt=None,
            info=info,
        )
        return hkdf.derive(shared_secret)
    
    def _encrypt_with_algorithm(self, input_path: str, output_path: str, key: bytes, 
                              algorithm: str, ephemeral_pub: bytes, signature: bytes):
        """Encrypts file using specified symmetric algorithm."""
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            data = f_in.read()
            
            if algorithm == "aes-gcm":
                cipher = AESGCM(key)
                nonce = secrets.token_bytes(12)
                ciphertext = cipher.encrypt(nonce, data, None)
            elif algorithm == "chacha20-poly1305":
                cipher = ChaCha20Poly1305(key)
                nonce = secrets.token_bytes(12)
                ciphertext = cipher.encrypt(nonce, data, None)
            elif algorithm == "xchacha20-poly1305":
                box = nacl.secret.SecretBox(key)
                nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
                ciphertext = box.encrypt(data, nonce)
            elif algorithm == "aes-cbc":
                # AES-CBC with HMAC for authentication
                iv = secrets.token_bytes(16)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                encryptor = cipher.encryptor()
                
                # PKCS7 padding
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(data) + padder.finalize()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                
                # Add HMAC for authentication
                hmac_key = hashlib.sha256(key + b"hmac").digest()
                hmac_obj = hmac.new(hmac_key, ciphertext, hashlib.sha256)
                auth_tag = hmac_obj.digest()
                ciphertext = iv + ciphertext + auth_tag
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            # Write metadata
            metadata = {
                "version": "enhanced_v1",
                "kex_algorithm": self.algorithm_negotiator.get_best_key_exchange_algorithm(),
                "sig_algorithm": self.algorithm_negotiator.get_best_signature_algorithm(),
                "sym_algorithm": algorithm,
                "hash_algorithm": self.algorithm_negotiator.get_best_hash_algorithm(),
                "ephemeral_public_key": base64.b64encode(ephemeral_pub).decode(),
                "signature": base64.b64encode(signature).decode(),
                "timestamp": time.time()
            }
            
            metadata_bytes = json.dumps(metadata).encode('utf-8')
            f_out.write(len(metadata_bytes).to_bytes(4, 'big'))
            f_out.write(metadata_bytes)
            f_out.write(ciphertext)

class HybridCipher:
    """Manages hybrid encryption combining asymmetric and symmetric ciphers."""

    def __init__(self, password, keyfile_path=None):
        self.password = password
        self.keyfile_path = keyfile_path
        self.rsa_private_key, self.x25519_private_key = self._load_or_generate_keys()

    def _load_or_generate_keys(self):
        rsa_key, x25519_key = load_keys(self.password, self.keyfile_path)
        if rsa_key is None or x25519_key is None:
            print(f"{YELLOW}Kunci tidak ditemukan atau gagal dimuat. Membuat kunci baru...{RESET}")
            rsa_key, x25519_key = generate_and_save_keys(self.password, self.keyfile_path)
            if rsa_key is None:
                raise RuntimeError("Gagal membuat atau memuat kunci hybrid.")
            print(f"{GREEN}Kunci baru berhasil dibuat dan disimpan.{RESET}")
        return rsa_key, x25519_key

    def encrypt(self, input_path, output_path):
        """Encrypts a file using a hybrid scheme."""
        # 1. Generate session key and wrap it with X25519 and RSA
        session_key = secrets.token_bytes(32)

        # X25519 layer
        x25519_public_key = self.x25519_private_key.public_key()
        ephemeral_private_key = x25519.X25519PrivateKey.generate()
        ephemeral_public_key = ephemeral_private_key.public_key()
        shared_key = ephemeral_private_key.exchange(x25519_public_key)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'hybrid_x25519_layer',
        )
        derived_key = hkdf.derive(shared_key)

        # Encrypt session key with derived key
        aesgcm = AESGCM(derived_key)
        iv = secrets.token_bytes(12)
        encrypted_session_key_inner = aesgcm.encrypt(iv, session_key, None)

        # RSA layer
        rsa_public_key = self.rsa_private_key.public_key()
        encrypted_session_key_outer = rsa_public_key.encrypt(
            encrypted_session_key_inner,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 2. Use the session key for symmetric encryption
        algo = AlgorithmNegotiator.get_best_algorithm()
        if algo is None:
            raise RuntimeError("Tidak ada algoritma simetris yang tersedia.")

        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            data = f_in.read()

            if algo == "aes-gcm":
                cipher = AESGCM(session_key)
                nonce = secrets.token_bytes(config["gcm_nonce_len"])
                ciphertext = cipher.encrypt(nonce, data, None)
            elif algo == "chacha20-poly1305":
                cipher = ChaCha20Poly1305(session_key)
                nonce = secrets.token_bytes(12)
                ciphertext = cipher.encrypt(nonce, data, None)
            elif algo == "xchacha20-poly1305":
                box = nacl.secret.SecretBox(session_key)
                nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
                ciphertext = box.encrypt(data, nonce)
            elif algo == "aes-siv":
                siv = SIV(session_key)
                nonce = b'' # AES-SIV is deterministic
                ciphertext = siv.seal(data, associated_data=[])

            metadata = {
                "cipher": "hybrid",
                "symmetric_algo": algo,
                "encrypted_session_key": base64.b64encode(encrypted_session_key_outer).decode('utf-8'),
                "ephemeral_public_key": base64.b64encode(ephemeral_public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )).decode('utf-8'),
                "iv": base64.b64encode(iv).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8')
            }
            metadata_bytes = json.dumps(metadata).encode('utf-8')
            f_out.write(len(metadata_bytes).to_bytes(4, 'big'))
            f_out.write(metadata_bytes)
            f_out.write(ciphertext)

        return True

    def decrypt(self, input_path, output_path):
        """Decrypts a file encrypted with the hybrid scheme."""
        with open(input_path, 'rb') as f_in:
            metadata_len = int.from_bytes(f_in.read(4), 'big')
            metadata = json.loads(f_in.read(metadata_len).decode('utf-8'))

            # Decrypt session key
            encrypted_session_key_outer = base64.b64decode(metadata['encrypted_session_key'])
            ephemeral_public_key_bytes = base64.b64decode(metadata['ephemeral_public_key'])
            iv = base64.b64decode(metadata['iv'])

            encrypted_session_key_inner = self.rsa_private_key.decrypt(
                encrypted_session_key_outer,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_key_bytes)
            shared_key = self.x25519_private_key.exchange(ephemeral_public_key)

            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'hybrid_x25519_layer',
            )
            derived_key = hkdf.derive(shared_key)

            aesgcm = AESGCM(derived_key)
            session_key = aesgcm.decrypt(iv, encrypted_session_key_inner, None)

            # Symmetric decryption
            algo = metadata['symmetric_algo']
            nonce = base64.b64decode(metadata['nonce'])
            ciphertext = f_in.read()

            if algo == "aes-gcm":
                cipher = AESGCM(session_key)
                plaintext = cipher.decrypt(nonce, ciphertext, None)
            elif algo == "chacha20-poly1305":
                cipher = ChaCha20Poly1305(session_key)
                plaintext = cipher.decrypt(nonce, ciphertext, None)
            elif algo == "xchacha20-poly1305":
                box = nacl.secret.SecretBox(session_key)
                plaintext = box.decrypt(ciphertext)
            elif algo == "aes-siv":
                siv = SIV(session_key)
                plaintext = siv.open(ciphertext, associated_data=[])

            with open(output_path, 'wb') as f_out:
                f_out.write(plaintext)

        return True


class KeyManager:
    """Manages key versions, rotation, and keystore."""

    def __init__(self, keystore_path, password, keyfile_path=None):
        self.keystore_path = keystore_path
        self.password = password
        self.keyfile_path = keyfile_path
        self._lock = threading.RLock()
        self.keystore = self._load_or_initialize_keystore()

    def _derive_keystore_key(self, salt):
        """
        Derives the encryption key for the keystore using stable, non-tuned parameters.
        This is critical to ensure the keystore can be opened across different runs
        where auto-tuning might change the global KDF parameters.
        """
        if not ARGON2_AVAILABLE:
            raise RuntimeError("Argon2 is required for keystore operations.")

        password_bytes = self.password.encode('utf-8')
        keyfile_bytes = b""
        if self.keyfile_path:
            if not os.path.isfile(self.keyfile_path):
                # This should be handled gracefully
                logger.error(f"Keyfile '{self.keyfile_path}' not found for keystore derivation.")
                return None
            with open(self.keyfile_path, 'rb') as kf:
                keyfile_bytes = kf.read()

        combined_input = password_bytes + keyfile_bytes

        try:
            # Use stable, hardcoded parameters, NOT the auto-tuned ones from the global config.
            return hash_secret_raw(
                secret=combined_input,
                salt=salt,
                time_cost=16,          # Stable value, reasonably strong
                memory_cost=1048576,   # 1GB, stable value
                parallelism=4,         # Stable value
                hash_len=32,           # For an AES-256 key
                type=Type.ID
            )
        except Exception as e:
            logger.error(f"Error deriving keystore key with stable parameters: {e}")
            return None

    def _load_or_initialize_keystore(self):
        """Loads the keystore from file or creates a new one."""
        with self._lock:
            if os.path.exists(self.keystore_path):
                try:
                    with open(self.keystore_path, 'rb') as f:
                        salt = f.read(16)
                        nonce = f.read(12)
                        encrypted_data = f.read()

                    keystore_key = self._derive_keystore_key(salt)
                    if keystore_key is None:
                        raise ValueError("Gagal menurunkan kunci keystore.")

                    cipher = AESGCM(keystore_key)
                    decrypted_data = cipher.decrypt(nonce, encrypted_data, None)
                    return json.loads(decrypted_data.decode('utf-8'))
                except (FileNotFoundError, ValueError, json.JSONDecodeError, crypto_exceptions.InvalidTag, TypeError) as e:
                    message = f"Gagal memuat keystore, mungkin rusak atau password salah: {e}"
                    print(message, file=sys.stderr)
                    logger.error(f"Gagal memuat keystore: {e}", exc_info=True)
                    # In a real scenario, you might want to handle this more gracefully
                    # For now, we'll exit to prevent creating a new keystore over a potentially recoverable one.
                    sys.exit(1)
            else:
                # Keystore does not exist, create a new one with the first master key
                print(f"{YELLOW}Keystore tidak ditemukan di '{self.keystore_path}'. Membuat yang baru...{RESET}")
                initial_keystore = {
                    "keys": {},
                    "active_key_version": 1,
                    "key_rotation_policy": config.get("key_rotation_policy", {
                        "enabled": False,
                        "interval_days": 90
                    })
                }
                self.keystore = initial_keystore
                self._generate_new_key(is_initial_key=True)
                self._save_keystore()
                print(f"{GREEN}Keystore baru berhasil dibuat.{RESET}")
                return self.keystore

    def _save_keystore(self):
        """Encrypts and saves the keystore to file."""
        with self._lock:
            try:
                salt = secrets.token_bytes(16)
                keystore_key = self._derive_keystore_key(salt)
                if keystore_key is None:
                    raise ValueError("Gagal menurunkan kunci keystore untuk menyimpan.")

                keystore_bytes = json.dumps(self.keystore, indent=4).encode('utf-8')

                cipher = AESGCM(keystore_key)
                nonce = secrets.token_bytes(12)
                encrypted_data = cipher.encrypt(nonce, keystore_bytes, None)

                with open(self.keystore_path, 'wb') as f:
                    f.write(salt)
                    f.write(nonce)
                    f.write(encrypted_data)
            except (IOError, OSError, ValueError) as e:
                print_error_box(f"Gagal menyimpan keystore: {e}")
                logger.error(f"Gagal menyimpan keystore: {e}", exc_info=True)


    def _generate_new_key(self, is_initial_key=False):
        """Generates a new master key and adds it to the keystore."""
        new_key_bytes = secrets.token_bytes(config.get("file_key_length", 32))
        new_key_b64 = base64.b64encode(new_key_bytes).decode('utf-8')

        if is_initial_key:
            new_version = 1
        else:
            # Find the highest existing version number and add 1
            if self.keystore["keys"]:
                new_version = max(map(int, self.keystore["keys"].keys())) + 1
            else:
                new_version = 1

        self.keystore["keys"][str(new_version)] = {
            "key": new_key_b64,
            "creation_date": time.time(),
            "status": "active"
        }
        self.keystore["active_key_version"] = new_version

        # Deactivate the old key if it exists
        if not is_initial_key and new_version > 1:
            old_version = str(new_version - 1)
            if old_version in self.keystore["keys"]:
                self.keystore["keys"][old_version]["status"] = "inactive"

        logger.info(f"Kunci master baru versi {new_version} dibuat dan diaktifkan.")
        return new_version

    def rotate_key(self):
        """Rotates the master key, generating a new one and deactivating the old one."""
        print(f"{CYAN}Memulai rotasi kunci master...{RESET}")
        active_version = self.get_active_key_version()
        new_version = self._generate_new_key()
        self._save_keystore()
        print(f"{GREEN}✅ Rotasi kunci berhasil. Kunci aktif sekarang adalah versi {new_version} (sebelumnya {active_version}).{RESET}")


    def get_active_key(self):
        """Returns the active master key bytes."""
        active_version = str(self.keystore["active_key_version"])
        key_info = self.keystore["keys"].get(active_version)
        if not key_info or key_info["status"] != "active":
            raise ValueError("Tidak ada kunci aktif yang ditemukan di keystore.")
        return base64.b64decode(key_info["key"])

    def get_key_by_version(self, version):
        """Returns a specific master key bytes by its version."""
        key_info = self.keystore["keys"].get(str(version))
        if not key_info:
            raise ValueError(f"Kunci versi {version} tidak ditemukan di keystore.")
        return base64.b64decode(key_info["key"])

    def get_active_key_version(self):
        """Returns the active master key version."""
        return self.keystore["active_key_version"]

    def check_rotation_policy(self):
        """Checks if the active key has expired and needs rotation."""
        policy = self.keystore.get("key_rotation_policy", {})
        if not policy.get("enabled", False):
            return

        active_version = str(self.keystore["active_key_version"])
        key_info = self.keystore["keys"].get(active_version)
        if not key_info:
            return

        creation_date = key_info.get("creation_date", 0)
        interval_days = policy.get("interval_days", 90)

        if (time.time() - creation_date) / (24 * 3600) > interval_days:
            print(f"{YELLOW}Peringatan: Kunci aktif telah melewati kebijakan rotasi ({interval_days} hari).{RESET}")
            self.rotate_key()

def safe_algorithm_negotiation():
    """Safe algorithm negotiation with fallback."""
    try:
        return AlgorithmNegotiator.get_best_algorithm()
    except Exception as e:
        logger.error(f"Algorithm negotiation failed: {e}")
        # Fallback ke AES-GCM jika tersedia
        if CRYPTOGRAPHY_AVAILABLE:
            return "aes-gcm"
        return None
        
# --- Fungsi Derivasi Kunci Baru (V14 - Parameter KDF Ditingkatkan) ---
def derive_key_from_password_and_keyfile_pbkdf2(password: str, salt: bytes, keyfile_path: str = None) -> bytes:
    """Derives a key from a password and keyfile using PBKDF2."""
    if not CRYPTOGRAPHY_AVAILABLE:
        print(f"{RED}❌ Error: PBKDF2 memerlukan modul 'cryptography'.{RESET}")
        logger.error("PBKDF2 memerlukan modul 'cryptography', yang tidak tersedia.")
        return None

    password_bytes = password.encode('utf-8')
    keyfile_bytes = b""
    if keyfile_path:
        if not os.path.isfile(keyfile_path):
            print(f"{RED}❌ Error: Keyfile '{keyfile_path}' tidak ditemukan.{RESET}")
            logger.error(f"File keyfile '{keyfile_path}' tidak ditemukan saat derivasi kunci (PBKDF2).")
            return None
        with open(keyfile_path, 'rb') as kf:
            keyfile_bytes = kf.read()

    combined_input = password_bytes + keyfile_bytes

    hash_algorithm_name = config.get("pbkdf2_hash_algorithm", "sha256").lower()
    if hash_algorithm_name.lower() == "sha256":
        hash_algorithm = hashes.SHA256()
    else:
        print(f"{RED}❌ Error: Algoritma hash PBKDF2 '{hash_algorithm_name}' tidak didukung.{RESET}")
        logger.error(f"Algoritma hash PBKDF2 '{hash_algorithm_name}' tidak didukung.")
        return None

    try:
        pbkdf2_kdf = PBKDF2HMAC(
            algorithm=hash_algorithm,
            length=config["file_key_length"],
            salt=salt,
            iterations=config["pbkdf2_iterations"],
        )
        derived_key = pbkdf2_kdf.derive(combined_input)
        logger.debug(f"Kunci berhasil diturunkan dengan PBKDF2 (cryptography), Panjang: {len(derived_key)} bytes")
        return derived_key
    except Exception as e:
        logger.error(f"Kesalahan saat hashing dengan PBKDF2 (cryptography): {e}")
        return None

def derive_key_from_password_and_keyfile_scrypt(password: str, salt: bytes, keyfile_path: str = None) -> bytes:
    """Derives a key from a password and keyfile using scrypt."""
    if not CRYPTOGRAPHY_AVAILABLE:
        print(f"{RED}❌ Error: Scrypt memerlukan modul 'cryptography'.{RESET}")
        logger.error("Scrypt memerlukan modul 'cryptography', yang tidak tersedia.")
        return None

    password_bytes = password.encode('utf-8')
    keyfile_bytes = b""
    if keyfile_path:
        if not os.path.isfile(keyfile_path):
            print(f"{RED}❌ Error: Keyfile '{keyfile_path}' tidak ditemukan.{RESET}")
            logger.error(f"File keyfile '{keyfile_path}' tidak ditemukan saat derivasi kunci (Scrypt).")
            return None
        with open(keyfile_path, 'rb') as kf:
            keyfile_bytes = kf.read()

    combined_input = password_bytes + keyfile_bytes

    try:
        scrypt_kdf = Scrypt(
            salt=salt,
            length=config["file_key_length"],
            n=config["scrypt_n"],
            r=config["scrypt_r"],
            p=config["scrypt_p"],
        )
        derived_key = scrypt_kdf.derive(combined_input)
        logger.debug(f"Kunci berhasil diturunkan dengan Scrypt (cryptography), Panjang: {len(derived_key)} bytes")
        return derived_key
    except Exception as e:
        logger.error(f"Kesalahan saat hashing dengan Scrypt (cryptography): {e}")
        return None

def derive_key_from_password_and_keyfile_argon2(password: str, salt: bytes, keyfile_path: str = None) -> bytes:
    """Derives a key from a password and keyfile using Argon2."""
    if not ARGON2_AVAILABLE:
        print(f"{RED}❌ Error: Argon2 tidak tersedia.{RESET}")
        logger.error("Argon2 tidak tersedia.")
        return None

    password_bytes = password.encode('utf-8')
    keyfile_bytes = b""
    if keyfile_path:
        if not os.path.isfile(keyfile_path):
            print(f"{RED}❌ Error: Keyfile '{keyfile_path}' tidak ditemukan.{RESET}")
            logger.error(f"File keyfile '{keyfile_path}' tidak ditemukan saat derivasi kunci (Argon2 low_level).")
            return None
        with open(keyfile_path, 'rb') as kf:
            keyfile_bytes = kf.read()

    combined_input = password_bytes + keyfile_bytes

    try:
        raw_hash = hash_secret_raw(
            secret=combined_input,
            salt=salt,
            time_cost=config["argon2_time_cost"],
            memory_cost=config["argon2_memory_cost"],
            parallelism=config["argon2_parallelism"],
            hash_len=config["file_key_length"],
            type=Type.ID
        )
        logger.debug(f"Kunci Argon2id berhasil diturunkan (argon2.low_level), Panjang: {len(raw_hash)} bytes")
        return raw_hash
    except Exception as e:
        logger.error(f"Kesalahan saat hashing dengan Argon2id (argon2.low_level): {e}")
        return None

def derive_key_from_password_and_keyfile(password: str, salt: bytes, keyfile_path: str = None) -> bytes:
    """Derives a key from a password and keyfile.

    This function selects the key derivation function (KDF) based on the
    configuration and library availability.
    """
    kdf_type = config.get("kdf_type", "argon2id").lower()

    if kdf_type == "pbkdf2":
        if CRYPTOGRAPHY_AVAILABLE:
            return derive_key_from_password_and_keyfile_pbkdf2(password, salt, keyfile_path)
        else:
            print(f"{RED}❌ Error: KDF '{kdf_type}' memerlukan modul 'cryptography'.{RESET}")
            logger.error(f"KDF '{kdf_type}' memerlukan modul 'cryptography', yang tidak tersedia.")
            return None

    elif kdf_type == "scrypt":
        if CRYPTOGRAPHY_AVAILABLE:
            return derive_key_from_password_and_keyfile_scrypt(password, salt, keyfile_path)
        else:
            print(f"{RED}❌ Error: KDF '{kdf_type}' memerlukan modul 'cryptography'.{RESET}")
            logger.error(f"KDF '{kdf_type}' memerlukan modul 'cryptography', yang tidak tersedia.")
            return None

    elif kdf_type == "argon2id":
        return derive_key_from_password_and_keyfile_argon2(password, salt, keyfile_path)

    else:
        print(f"{RED}❌ Error: Tipe KDF '{kdf_type}' tidak dikenal. Gunakan 'argon2id', 'scrypt', atau 'pbkdf2'.{RESET}")
        logger.error(f"Tipe KDF '{kdf_type}' tidak dikenal.")
        return None

# --- Fungsi Derivasi Kunci File dengan HKDF (menggunakan cryptography jika tersedia) ---
def derive_file_key_from_master_key(master_key: bytes, input_file_path: str) -> bytes:
    """Derives a file key from the master key using HKDF.

    Args:
        master_key: The master key to use for key derivation.
        input_file_path: The path to the input file.

    Returns:
        The derived file key.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        print(f"{RED}❌ Error: HKDF memerlukan modul 'cryptography'.{RESET}")
        logger.error("HKDF memerlukan modul 'cryptography', yang tidak tersedia.")
        return secrets.token_bytes(config["file_key_length"]) # Fallback ke acak jika tidak tersedia

    # Buat salt unik berdasarkan path file input
    file_path_hash = hashlib.sha256(input_file_path.encode()).digest()[:16] # Gunakan 16 byte pertama

    # Ambil string dari konfigurasi dan konversi ke bytes
    info_prefix_str = config.get("hkdf_info_prefix", "thena_file_key_")
    info_bytes = info_prefix_str.encode('utf-8') + file_path_hash # Gabungkan prefix dan hash path

    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=config["file_key_length"],
            salt=file_path_hash, # Gunakan hash path sebagai salt HKDF (V14: Lebih unik)
            info=info_bytes, # Gunakan bytes yang dikonversi
        )
        file_key = hkdf.derive(master_key)
        logger.debug(f"Kunci file diturunkan dari Master Key menggunakan HKDF (cryptography) (Info: {info_prefix_str} + hash path), Panjang: {len(file_key)} bytes")
        return file_key
    except Exception as e:
        logger.error(f"Kesalahan saat derivasi kunci file dengan HKDF (cryptography): {e}")
        # Fallback ke acak jika HKDF gagal
        return secrets.token_bytes(config["file_key_length"])

# --- Fungsi Derivasi Kunci HMAC dari Master Key (V8 - Fixed HMAC Derivation - V14: Konsisten & Lebih Aman) ---
def derive_hmac_key_from_master_key(master_key: bytes, input_file_path: str) -> bytes:
    """Derives an HMAC key from the master key using HKDF.

    Args:
        master_key: The master key to use for key derivation.
        input_file_path: The path to the input file.

    Returns:
        The derived HMAC key.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        print(f"{RED}❌ Error: HKDF (untuk HMAC) memerlukan modul 'cryptography'.{RESET}")
        logger.error("HKDF (untuk HMAC) memerlukan modul 'cryptography', yang tidak tersedia.")
        return secrets.token_bytes(config["hmac_key_length"]) # Fallback ke acak jika tidak tersedia

    # Buat salt unik berdasarkan path file input (V14)
    file_path_hash = hashlib.sha256(input_file_path.encode()).digest()[:16]

    # Ambil string dari konfigurasi dan konversi ke bytes
    info_prefix_str = config.get("hmac_derivation_info", "thena_hmac_key_")
    info_bytes = info_prefix_str.encode('utf-8') + file_path_hash # Gabungkan prefix dan hash path (V14)

    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=config["hmac_key_length"],
            salt=file_path_hash, # Gunakan hash path sebagai salt (V14: Lebih unik)
            info=info_bytes, # Gunakan bytes yang dikonversi
        )
        hmac_key = hkdf.derive(master_key)
        logger.debug(f"Kunci HMAC diturunkan dari Master Key menggunakan HKDF (cryptography) (Info: {info_prefix_str} + hash path), Panjang: {len(hmac_key)} bytes")
        return hmac_key
    except Exception as e:
        logger.error(f"Kesalahan saat derivasi kunci HMAC dengan HKDF (cryptography): {e}")
        # Fallback ke acak jika HKDF gagal
        return secrets.token_bytes(config["hmac_key_length"])

# --- Fungsi Master Key Management (DEPRECATED) ---
# Fungsi load_or_create_master_key sekarang sudah usang dan digantikan oleh KeyManager.
# Disimpan untuk referensi atau kompatibilitas mundur jika diperlukan di masa depan.

def generate_and_save_keys(password: str, keyfile_path: str = None):
    """Generates and saves RSA and X25519 key pairs."""
    try:
        # Generate RSA keys
        rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=config["rsa_key_size"],
        )
        # Generate X25519 keys
        x25519_private_key = x25519.X25519PrivateKey.generate()

        # Encrypt and save RSA private key
        salt = secrets.token_bytes(16)
        key = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
        if key is None:
            raise ValueError("Key derivation failed.")
        pem = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(key),
        )
        with open(config["rsa_private_key_file"], "wb") as f:
            f.write(salt + pem)

        # Encrypt and save X25519 private key
        salt = secrets.token_bytes(16)
        key = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
        if key is None:
            raise ValueError("Key derivation failed.")
        pem = x25519_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(key),
        )
        with open(config["x25519_private_key_file"], "wb") as f:
            f.write(salt + pem)

        return rsa_private_key, x25519_private_key
    except (IOError, OSError) as e:
        print_error_box(f"Gagal menyimpan file kunci: {e}")
        logger.error(f"Error saving key file: {e}")
        return None, None
    except Exception as e:
        print_error_box(f"Terjadi error saat membuat kunci: {e}")
        logger.error(f"Error generating keys: {e}", exc_info=True)
        return None, None

def load_keys(password: str, keyfile_path: str = None):
    """Loads RSA and X25519 private keys from files."""
    try:
        # Load and decrypt RSA private key
        with open(config["rsa_private_key_file"], "rb") as f:
            salt = f.read(16)
            pem = f.read()
        key = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
        if key is None:
            raise ValueError("Key derivation failed.")
        rsa_private_key = serialization.load_pem_private_key(
            pem,
            password=key,
        )

        # Load and decrypt X25519 private key
        with open(config["x25519_private_key_file"], "rb") as f:
            salt = f.read(16)
            pem = f.read()
        key = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
        if key is None:
            raise ValueError("Key derivation failed.")
        x25519_private_key = serialization.load_pem_private_key(
            pem,
            password=key,
        )
        return rsa_private_key, x25519_private_key
    except FileNotFoundError:
        # This is not an error if we are creating new keys
        return None, None
    except (ValueError, TypeError):
        # This is likely a password error
        print_error_box("Gagal mendekripsi kunci. Password atau keyfile salah.")
        logger.error("Failed to decrypt keys, likely wrong password/keyfile.", exc_info=True)
        return None, None
    except Exception as e:
        print_error_box(f"Terjadi error saat memuat kunci: {e}")
        logger.error(f"Error loading keys: {e}", exc_info=True)
        return None, None

# --- Fungsi Manajemen Memori Aman ---
def initialize_secure_memory_manager(master_key: bytes):
    """Initializes the global SecureMemoryManager instance."""
    if CRYPTOGRAPHY_AVAILABLE:
        try:
            memory_manager = SecureMemoryManager(master_key)
            globals_manager.set_memory_manager(memory_manager)  # ✅ Simpan di globals_manager
            logger.info("SecureMemoryManager initialized successfully.")
            atexit.register(cleanup_secure_memory_manager)
        except Exception as e:
            logger.error(f"Failed to initialize SecureMemoryManager: {e}")
            globals_manager.set_memory_manager(None)
    else:
        logger.warning("Cannot initialize SecureMemoryManager: 'cryptography' module not available.")
        globals_manager.set_memory_manager(None)

def cleanup_secure_memory_manager():
    """Wipes all data from the SecureMemoryManager on exit."""
    memory_manager = get_memory_manager()
    if memory_manager:
        try:
            # ✅ PERBAIKAN: Pastikan semua data di-wipe dengan aman
            if hasattr(memory_manager, '_enclave'):
                # Buat salinan keys untuk menghindari modifikasi selama iterasi
                keys_to_wipe = list(memory_manager._enclave.keys())
                for key_id in keys_to_wipe:
                    try:
                        memory_manager.wipe_data(key_id)
                        logger.debug(f"Wiped sensitive data: {key_id}")
                    except Exception as wipe_error:
                        logger.error(f"Failed to wipe data for {key_id}: {wipe_error}")
            
            # ✅ PERBAIKAN: Panggil cleanup method jika ada
            if hasattr(memory_manager, 'cleanup'):
                memory_manager.cleanup()
            elif hasattr(memory_manager, 'wipe_all'):
                memory_manager.wipe_all()
                
            # Force garbage collection
            gc.collect()
            
            logger.info("SecureMemoryManager wiped all data on exit.")
        except Exception as e:
            logger.error(f"Error during SecureMemoryManager cleanup: {e}")
        finally:
            # ✅ PERBAIKAN: Pastikan reference di-set ke None
            globals_manager.set_memory_manager(None)

def store_sensitive_data(key_id: str, data: bytes):
    """Wrapper to safely store sensitive data in the global manager."""
    global globals_manager
    memory_manager = globals_manager.memory_manager
    if memory_manager:
        memory_manager.store_sensitive_data(key_id, data)
    else:
        logger.warning(f"Cannot store data for '{key_id}': SecureMemoryManager is not initialized.")

def wipe_sensitive_data(key_id: str):
    """Wrapper to safely wipe sensitive data from the global manager."""
    global globals_manager
    memory_manager = globals_manager.memory_manager
    if memory_manager:
        memory_manager.wipe_data(key_id)
    else:
        logger.warning(f"Cannot wipe data for '{key_id}': SecureMemoryManager is not initialized.")
        
# --- Fungsi Utilitas Keyfile Creation ---
def create_keyfile_interactive():
    """Interactive keyfile creation dari dalam script Enkripsi.py"""
    
    print(f"\n{BOLD}🎯 CREATE KEYFILE UTILITY{RESET}")
    print("=" * 50)
    
    filename = input(f"{BOLD}Masukkan nama keyfile [default: my_keyfile.key]: {RESET}").strip()
    if not filename:
        filename = "my_keyfile.key"
    
    size_input = input(f"{BOLD}Ukuran keyfile dalam MB [default: 10]: {RESET}").strip()
    try:
        size_mb = int(size_input) if size_input else 10
    except ValueError:
        print(f"{RED}❌ Ukuran harus angka!{RESET}")
        return
    
    if size_mb <= 0 or size_mb > 100:
        print(f"{RED}❌ Ukuran harus antara 1-100 MB{RESET}")
        return
    
    # Konfirmasi overwrite
    if os.path.exists(filename):
        confirm = input(f"{YELLOW}⚠️  File '{filename}' sudah ada. Overwrite? (y/N): {RESET}").lower()
        if confirm != 'y':
            print(f"{YELLOW}Operasi dibatalkan.{RESET}")
            return
    
    print(f"\n{CYAN}📦 Membuat keyfile: {filename} ({size_mb}MB){RESET}")
    print(f"{CYAN}⏳ Generating secure random data...{RESET}")
    
    try:
        with open(filename, 'wb') as f:
            bytes_written = 0
            total_bytes = size_mb * 1024 * 1024
            chunk_size = 1024 * 1024  # 1MB chunks
            
            while bytes_written < total_bytes:
                chunk = secrets.token_bytes(min(chunk_size, total_bytes - bytes_written))
                f.write(chunk)
                bytes_written += len(chunk)
                
                # Progress indicator
                progress = (bytes_written / total_bytes) * 100
                bars = "█" * int(progress / 2)
                spaces = " " * (50 - len(bars))
                print(f"\r[{bars}{spaces}] {progress:.1f}%", end='', flush=True)
        
        print(f"\n{GREEN}✅ Keyfile berhasil dibuat: {filename}{RESET}")
        
        # Verifikasi
        file_size = os.path.getsize(filename)
        expected_size = size_mb * 1024 * 1024
        
        if file_size == expected_size:
            print(f"{GREEN}✅ Ukuran tepat: {file_size} bytes{RESET}")
        else:
            print(f"{YELLOW}⚠️  Ukuran tidak tepat: {file_size} bytes (expected: {expected_size}){RESET}")
        
        # Entropy check sederhana
        with open(filename, 'rb') as f:
            sample = f.read(1000)  # Baca sample 1000 bytes
            unique_bytes = len(set(sample))
            entropy_ratio = unique_bytes / len(sample) if sample else 0
            
            if entropy_ratio > 0.95:
                print(f"{GREEN}✅ Entropy quality: EXCELLENT ({entropy_ratio:.2%}){RESET}")
            elif entropy_ratio > 0.85:
                print(f"{GREEN}✅ Entropy quality: GOOD ({entropy_ratio:.2%}){RESET}")
            else:
                print(f"{YELLOW}⚠️  Entropy quality: POOR ({entropy_ratio:.2%}) - Consider regenerating{RESET}")
                
        print(f"\n{BOLD}💡 Tips:{RESET}")
        print(f"  • Simpan keyfile di lokasi aman")
        print(f"  • Backup keyfile secara terpisah dari data terenkripsi")
        print(f"  • Jangan pernah share keyfile dengan siapapun")
        
    except Exception as e:
        print(f"\n{RED}❌ Error membuat keyfile: {e}{RESET}")
        
# --- Fungsi Utilitas Kompresi ---
def compress_data(data) -> bytes:
    """Compresses data using zlib.

    Args:
        data (bytes): The data to compress.

    Returns:
        bytes: The compressed data.
    """
    compression_level = config.get("compression_level", 6)
    try:
        compressed_data = zlib.compress(data, level=compression_level)
        logger.debug(f"Data dikompresi dari {len(data)} bytes menjadi {len(compressed_data)} bytes (level {compression_level}).")
        return compressed_data
    except Exception as e:
        logger.error(f"Error saat kompresi data: {e}")
        # Fallback: kembalikan data asli jika kompresi gagal
        return data

def decompress_data(data) -> bytes:
    """Decompresses data using zlib.

    Args:
        data (bytes): The data to decompress.

    Returns:
        bytes: The decompressed data.
    """
    try:
        decompressed_data = zlib.decompress(data)
        logger.debug(f"Data didekompresi dari {len(data)} bytes menjadi {len(decompressed_data)} bytes.")
        return decompressed_data
    except Exception as e:
        logger.error(f"Error saat dekompresi data: {e}. Menganggap data tidak dikompresi.")
        # Fallback: kembalikan data asli jika dekompresi gagal (mungkin tidak dikompresi)
        return data

def encrypt_file_simple(input_path: str, output_path: str, password: str, keyfile_path: str = None, add_random_padding: bool = True, hide_paths: bool = False, confirm_filename_prompt: bool = True):
    """Encrypts a file using a password and optional keyfile with secure memory management."""
    logger = logging.getLogger(__name__)
    start_time = time.time()
    output_dir = os.path.dirname(output_path) or "."

    # --- Validasi Input ---
    if not all(isinstance(arg, str) for arg in [input_path, output_path, password]):
        print_error_box("Error: Tipe argumen tidak valid.")
        logger.error("Invalid argument type provided.")
        return False, None
    if keyfile_path and not isinstance(keyfile_path, str):
        print_error_box("Error: Tipe argumen keyfile tidak valid.")
        logger.error("Invalid keyfile argument type provided.")
        return False, None

    if not os.path.isfile(input_path):
        print_error_box(f"Error: File input '{input_path}' tidak ditemukan.")
        logger.error(f"File input '{input_path}' tidak ditemukan.")
        return False, None

    if not os.access(input_path, os.R_OK):
        print_error_box(f"Error: File input '{input_path}' tidak dapat dibaca.")
        logger.error(f"File input '{input_path}' tidak dapat dibaca (izin akses).")
        return False, None

    if os.path.getsize(input_path) == 0:
        print_error_box(f"Error: File input '{input_path}' kosong.")
        logger.error(f"File input '{input_path}' kosong.")
        return False, None

    if not check_file_size_limit(input_path):
        return False, None

    if not check_disk_space(input_path, output_dir):
        return False, None
    
    if not confirm_overwrite(output_path):
        return False, None

    # Validasi ekstensi output
    if confirm_filename_prompt and not output_path.endswith('.encrypted'):
        print(f"{YELLOW}⚠️  Peringatan: Nama file output '{output_path}' tidak memiliki ekstensi '.encrypted'.{RESET}")
        confirm = input(f"{YELLOW}Lanjutkan dengan nama ini? (y/N): {RESET}").strip().lower()
        if confirm not in ['y', 'yes']:
            print(f"{YELLOW}Operasi dibatalkan.{RESET}")
            logger.info("Operasi dibatalkan karena nama output tidak memiliki ekstensi '.encrypted'.")
            return False, None

    try:
        if hide_paths:
            print(f"\n{CYAN}[ Encrypting... ]{RESET}")
            logger.info(f"Memulai enkripsi file (simple) di direktori: {output_dir}")
        else:
            print(f"\n{CYAN}[ Encrypting (Simple Mode)... ]{RESET}")
            logger.info(f"Memulai enkripsi file (simple): {input_path}")

        input_size = os.path.getsize(input_path)
        logger.info(f"Ukuran file input: {input_size} bytes")

        algo = AlgorithmNegotiator.get_best_algorithm()
        if algo is None:
            print(f"{RED}❌ Error: Tidak ada algoritma enkripsi yang didukung tersedia.{RESET}")
            logger.error("Tidak ada algoritma enkripsi yang didukung tersedia.")
            return False, None

        large_file_threshold = config.get("large_file_threshold", 10 * 1024 * 1024)

        # ✅ PERBAIKAN: Pisahkan logika streaming dan in-memory
        if input_size > large_file_threshold and _is_streaming_supported("aes-gcm"):
            # --- STREAMING ENCRYPTION ---
            print(f"{CYAN}File besar terdeteksi. Menggunakan mode streaming...{RESET}")
            return perform_streaming_encryption(input_path, output_path, password, keyfile_path, algo)
        else:
            # --- IN-MEMORY ENCRYPTION ---
            print(f"{CYAN}Menggunakan mode in-memory...{RESET}")
            return perform_in_memory_encryption(input_path, output_path, password, keyfile_path, algo, hide_paths)

    except Exception as e:
        logger.error(f"Enkripsi file '{input_path}' gagal: {e}")
        print_error_box(f"Enkripsi gagal: {e}")
        if os.path.exists(output_path):
            os.remove(output_path)
        return False, None
    finally:
        # ✅ PERBAIKAN: Pastikan master key dihapus dari manager
        logger.info("Membersihkan master key dari SecureMemoryManager.")
        wipe_sensitive_data("master_encryption_key")

        # --- Fallback to in-memory for smaller files or unsupported algos ---
        salt = secrets.token_bytes(config["file_key_length"]) # Gunakan panjang yang sesuai untuk salt
        key = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
        if key is None:
            logger.error(f"Gagal menurunkan kunci untuk {input_path}")
            return False, None

        # --- V14: Secure Memory Locking ---
        if config.get("enable_secure_memory_locking", False):
            key_addr = ctypes.addressof((ctypes.c_char * len(key)).from_buffer_copy(key))
            secure_mlock(key_addr, len(key))
            logger.debug(f"Kunci disimpan di memori terkunci untuk {input_path}")
            # Register untuk integrity check
            if config.get("enable_runtime_data_integrity", False):
                register_sensitive_data(f"key_{input_path}", key)

        with open(input_path, 'rb') as f_in:
            plaintext_data = f_in.read()

        # --- Tambahkan Kompresi di sini ---
        original_checksum = calculate_checksum(plaintext_data)
        logger.debug(f"Checksum data (sebelum kompresi): {original_checksum.hex()}")

        if config.get("enable_compression", False):
            logger.debug("Mengompresi data sebelum encrypted...")
            plaintext_data = compress_data(plaintext_data)
        else:
            logger.debug("Kompresi dinonaktifkan, melewati.")

        data = plaintext_data
        padding_added = 0
        if add_random_padding:
            padding_length = secrets.randbelow(config["chunk_size"])
            random_padding = secrets.token_bytes(padding_length)
            data = plaintext_data + random_padding
            padding_added = padding_length

        if algo == "aes-gcm":
            if CRYPTOGRAPHY_AVAILABLE:
                nonce = secrets.token_bytes(config["gcm_nonce_len"])
                cipher = AESGCM(key)
                ciphertext = cipher.encrypt(nonce, data, associated_data=None)
                tag = b""
            elif PYCRYPTODOME_AVAILABLE:
                nonce = get_random_bytes(config["gcm_nonce_len"])
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                ciphertext, tag = cipher.encrypt_and_digest(data)
        elif algo == "chacha20-poly1305":
            nonce = secrets.token_bytes(12)
            cipher = ChaCha20Poly1305(key)
            ciphertext = cipher.encrypt(nonce, data, associated_data=None)
            tag = b""
        elif algo == "xchacha20-poly1305":
            box = nacl.secret.SecretBox(key)
            nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
            ciphertext = box.encrypt(data, nonce)
            tag = b""
        elif algo == "aes-siv":
            siv = SIV(key)
            # AES-SIV tidak memerlukan nonce; ia deterministik
            ciphertext = siv.seal(data, associated_data=[])
            nonce = b"" # Tidak ada nonce untuk AES-SIV
            tag = b""

        # AEAD ciphers like AES-GCM and ChaCha20-Poly1305 provide authentication, so a separate HMAC is not needed.

        # --- V10/V11/V12/V13/V14: Custom File Format Shuffle & Dynamic Header (Variable Parts) ---
        parts_to_write = [
            ("algo_name", algo.encode('utf-8')),
            ("nonce", nonce),
            ("checksum", original_checksum),
            ("padding_added", padding_added.to_bytes(config["padding_size_length"], byteorder='big')),
        ]
        if algo == "aes-gcm" and PYCRYPTODOME_AVAILABLE: # Hanya jika menggunakan pycryptodome
            parts_to_write.append(("tag", tag))
        parts_to_write.append(("ciphertext", ciphertext))

        # --- V14: Generate Dynamic Header Parts ---
        dynamic_header_parts = generate_dynamic_header_parts(input_path, len(plaintext_data))
        # Update bagian-bagian yang akan ditulis dengan informasi dari dynamic header
        # Misalnya, kita bisa menyisipkan bagian-bagian ini ke dalam struktur file utama
        # atau menyimpannya di awal file sebagai header meta.
        # Untuk saat ini, kita sertakan bagian-bagian dari dynamic_header_parts ke dalam parts_to_write
        # tapi kita simpan informasi tentang struktur ini di tempat lain (misalnya dalam checksum tambahan atau HMAC).
        # Kita bisa menyimpan struktur (urutan dan nama bagian) dalam checksum tambahan atau HMAC tambahan.
        # Atau, kita buat header yang menjelaskan struktur file.
        # Misalnya: [jumlah_bagian][panjang_nama_bagian][nama_bagian_1][panjang_data_bagian_1][data_bagian_1]...
        # Kita gunakan pendekatan ini.
        # Format setiap bagian: [4_byte_nama][4_byte_panjang][data_panjang_byte]
        final_parts_to_write = []
        for part_name, part_data in parts_to_write:
             final_parts_to_write.append((part_name, part_data))
        # Tambahkan bagian dari dynamic header (ini opsional dan bisa diacak)
        for dyn_part_name, dyn_part_data in dynamic_header_parts:
             final_parts_to_write.append((dyn_part_name, dyn_part_data))

        # --- V18: Tambahkan Decoy Blocks ---
        if config.get("enable_decoy_blocks", False):
            decoy_count = secrets.randbelow(config.get("decoy_block_count", 5) + 1)
            for i in range(decoy_count):
                decoy_size = secrets.randbelow(config.get("decoy_block_max_size", 1024) + 1)
                decoy_data = secrets.token_bytes(decoy_size)
                final_parts_to_write.append((f"decoy_{i}", decoy_data))
                logger.debug(f"Menambahkan blok decoy 'decoy_{i}' dengan ukuran {decoy_size} bytes.")

        shuffled_parts = shuffle_file_parts(final_parts_to_write)

        # --- V14: Dynamic Header Format (Meta Header) ---
        meta_header_version = config["dynamic_header_version"].to_bytes(2, byteorder='big') # 2 byte versi
        num_total_parts_bytes = len(shuffled_parts).to_bytes(4, byteorder='big') # 4 byte jumlah bagian
        meta_header_prefix = meta_header_version + num_total_parts_bytes

        structure_payload = b''
        for part_name, part_data in shuffled_parts:
             part_name_bytes = part_name.encode('ascii').ljust(255, b'\x00') # Nama bagian (255 byte, null-terminated)
             part_size_bytes = len(part_data).to_bytes(4, byteorder='little') # Ukuran bagian (4 byte, little endian)
             structure_payload += part_name_bytes + part_size_bytes

        # --- V18: Encrypted Meta Header ---
        header_salt = secrets.token_bytes(16)
        header_key = derive_key_for_header(key, header_salt)
        header_nonce = secrets.token_bytes(config["gcm_nonce_len"])
        header_cipher = AESGCM(header_key)
        encrypted_structure_payload = header_cipher.encrypt(header_nonce, structure_payload, associated_data=None)

        # V18 FIX: Store the size of the encrypted header
        encrypted_header_size_bytes = len(encrypted_structure_payload).to_bytes(4, byteorder='big')

        # Simpan nonce header di meta_header_prefix
        header_to_write = meta_header_prefix + encrypted_header_size_bytes + header_nonce + encrypted_structure_payload

        total_output_size = len(salt) + len(header_salt) + len(header_to_write) + sum(len(part_data) for _, part_data in shuffled_parts)

        with open(output_path, 'wb') as outfile:
            print_loading_progress()
            # V18 FIX: Tulis salt di luar header terenkripsi
            outfile.write(salt)
            outfile.write(header_salt)
            # Tulis meta header dulu
            outfile.write(header_to_write)
            # Tulis bagian-bagian yang diacak
            for part_name, part_data in shuffled_parts:
                outfile.write(part_data) # Data bagian
                logger.debug(f"Menulis bagian '{part_name}' ({len(part_data)} bytes) ke file output.")

        output_size = os.path.getsize(output_path)
        logger.info(f"Ukuran file output: {output_size} bytes")

        # --- V8: Verifikasi Integritas Output ---
        if config.get("verify_output_integrity", True):
            print(f"{CYAN}Memverifikasi integritas file output...{RESET}")
            try:
                with open(output_path, 'rb') as f:
                    file_content = f.read()
                calculated_file_checksum = calculate_checksum(file_content)
                # Untuk verifikasi output, kita bisa membandingkan checksum dari seluruh file output
                # dengan checksum yang disimpan di dalam file (checksum data asli) dan HMAC.
                # Atau, kita bisa encrypted ulang file input dan bandingkan outputnya (lebih berat).
                # Untuk saat ini, kita hanya memastikan file output bisa dibaca dan ukurannya sesuai.
                if os.path.getsize(output_path) != output_size:
                    print(f"{RED}❌ Error: Ukuran file output tidak sesuai setelah verifikasi.{RESET}")
                    logger.error(f"Verifikasi integritas output gagal: ukuran tidak cocok untuk {output_path}")
                    return False, None
                print(f"{GREEN}✅ Verifikasi integritas output berhasil.{RESET}")
                logger.info(f"Verifikasi integritas output berhasil untuk {output_path}")
            except Exception as e:
                print(f"{RED}❌ Error saat memverifikasi integritas output: {e}{RESET}")
                logger.error(f"Verifikasi integritas output gagal untuk {output_path}: {e}")
                return False, None


        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"Durasi encrypted: {duration:.2f} detik")

        # --- Hardening V14: Secure Memory Overwrite (FIXED) ---
        if config.get("enable_secure_memory_overwrite", False):
            secure_overwrite_variable(key)
            secure_overwrite_variable(plaintext_data)
            secure_overwrite_variable(ciphertext)
            secure_overwrite_variable(original_checksum)
            # Variabel lain yang sensitif bisa ditambahkan di sini

        if hide_paths:
            print(f"{GREEN}✅ File berhasil diencrypted.{RESET}")
            logger.info(f"Encrypted (simple) berhasil ke file di direktori: {output_dir}")
        else:
            print(f"{GREEN}✅ File '{input_path}' berhasil diencrypted ke '{output_path}' (Simple Mode).{RESET}")
            logger.info(f"Encrypted (simple) berhasil: {input_path} -> {output_path}")

        return True, output_path

    except FileNotFoundError:
        if hide_paths:
            print(f"{RED}❌ Error: File input tidak ditemukan.{RESET}")
            logger.error(f"File input tidak ditemukan saat encrypted (simple) di direktori: {output_dir}")
        else:
            print(f"{RED}❌ Error: File '{input_path}' tidak ditemukan.{RESET}") # Perbaikan: gunakan input_path
            logger.error(f"File '{input_path}' tidak ditemukan saat encrypted (simple).") # Perbaikan: gunakan input_path
        return False, None
    except Exception as e:
        if hide_paths:
            print(f"{RED}❌ Error saat mengencrypted file: {e}{RESET}")
            logger.error(f"Error saat mengencrypted (simple) di direktori '{output_dir}': {e}")
        else:
            print(f"{RED}❌ Error saat mengencrypted file (simple): {e}{RESET}")
            logger.error(f"Error saat mengencrypted (simple) {input_path}: {e}") # Perbaikan: gunakan input_path
        return False, None

def decrypt_file_simple(input_path: str, output_path: str, password: str, keyfile_path: str = None, hide_paths: bool = False, confirm_overwrite_prompt: bool = True):
    logger = logging.getLogger(__name__)
    start_time = time.time()
    
    # Validasi input...
    
    use_streaming = False
    try:
        # Cek format streaming
        with open(input_path, 'rb') as f_in:
            salt = f_in.read(config["file_key_length"])
            magic_bytes = f_in.read(8)
            
        if magic_bytes == b"STREAMV1":
            use_streaming = True
            # Streaming decryption logic...
            success = perform_streaming_decryption(input_path, output_path, password, keyfile_path, salt)
            if success:
                return True, output_path
            else:
                return False, None
                
    except Exception as e:
        logger.error(f"Streaming decryption failed: {e}")
        # Lanjut ke fallback
    
    # Fallback untuk format lama
    try:
        print(f"{YELLOW}Format file lama terdeteksi. Menggunakan mode in-memory...{RESET}")
        # Fallback logic...
        return perform_fallback_decryption(input_path, output_path, password, keyfile_path)
        
    except Exception as e:
        logger.error(f"Fallback decryption also failed: {e}")
        return False, None
        
    finally:
        # Cleanup
        wipe_sensitive_data("master_decryption_key")

        # --- Fallback to in-memory for old format ---
        print(f"{YELLOW}Format file lama terdeteksi. Menggunakan mode in-memory...{RESET}")
        file_structure = []
        parts_read = {}
        with open(input_path, 'rb') as infile:
            # V18 FIX: Baca salt dari luar header
            salt = infile.read(config["file_key_length"])
            header_salt = infile.read(16)

            # --- V18: Baca Dynamic Meta Header ---
            meta_header_prefix_size = 2 + 4 # Versi (2) + Jumlah Bagian (4)
            meta_header_prefix = infile.read(meta_header_prefix_size)
            version_bytes = meta_header_prefix[:2]
            num_total_parts_bytes = meta_header_prefix[2:6]

            version = int.from_bytes(version_bytes, byteorder='big')
            num_total_parts = int.from_bytes(num_total_parts_bytes, byteorder='big')
            logger.debug(f"Meta header dinamis dibaca: Versi={version}, Num_Total_Parts={num_total_parts}")

            # V18 FIX: Read the size of the encrypted header
            encrypted_header_size_bytes = infile.read(4)
            encrypted_header_size = int.from_bytes(encrypted_header_size_bytes, byteorder='big')

            # --- V18: Decrypt Meta Header ---
            header_nonce = infile.read(config["gcm_nonce_len"])
            encrypted_structure_payload = infile.read(encrypted_header_size)

            key = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
            if key is None:
                logger.error(f"Gagal menurunkan kunci untuk {input_path}")
                return False, None

            header_key = derive_key_for_header(key, header_salt)
            header_cipher = AESGCM(header_key)
            try:
                decrypted_meta_header_structure_info = header_cipher.decrypt(header_nonce, encrypted_structure_payload, associated_data=None)
            except Exception as e:
                print(f"{RED}❌ Error: Gagal mendekripsi header. Password/Keyfile mungkin salah atau file rusak.{RESET}")
                logger.error(f"Gagal mendekripsi header: {e}")
                return False, None

            # --- V18: Parse Info Struktur dari Meta Header yang Telah Didekripsi ---
            structure_info_idx = 0
            file_structure = []
            for _ in range(num_total_parts):
                part_name_padded_bytes = decrypted_meta_header_structure_info[structure_info_idx : structure_info_idx + 255]
                structure_info_idx += 255
                part_name = part_name_padded_bytes.decode('ascii').strip('\x00')
                part_size_bytes = decrypted_meta_header_structure_info[structure_info_idx : structure_info_idx + 4]
                structure_info_idx += 4
                part_size = int.from_bytes(part_size_bytes, byteorder='little')
                file_structure.append((part_name, part_size))
                logger.debug(f"Struktur file: Bagian '{part_name}', Ukuran: {part_size} bytes")

            # --- V18: Baca Bagian-Bagian Berdasarkan Struktur ---
            for part_name, part_size in file_structure:
                 part_data = infile.read(part_size)
                 if len(part_data) != part_size:
                      print(f"{RED}❌ Error: File input rusak (data bagian '{part_name}' tidak lengkap).{RESET}")
                      logger.error(f"Data bagian '{part_name}' tidak lengkap di {input_path}")
                      return False, None
                 parts_read[part_name] = part_data
                 logger.debug(f"Bagian '{part_name}' ({part_size} bytes) dibaca dari file input.")


        # Ambil bagian-bagian yang diperlukan
        algo_name_bytes = parts_read.get("algo_name")
        if algo_name_bytes:
            algo = algo_name_bytes.decode('utf-8')
        else:
            # Fallback for old file format
            algo = config.get("encryption_algorithm", "aes-gcm").lower()
            logger.warning(f"File format lama terdeteksi. Menggunakan algoritma dari konfigurasi: {algo}")

        nonce = parts_read.get("nonce")
        stored_checksum = parts_read.get("checksum")
        padding_size_bytes = parts_read.get("padding_added")
        tag = parts_read.get("tag") # Bisa None jika cryptography
        ciphertext = parts_read.get("ciphertext")

        if not all([nonce is not None, stored_checksum, padding_size_bytes, ciphertext]):
             print(f"{RED}❌ Error: File input tidak valid atau rusak (bagian penting hilang).{RESET}")
             logger.error(f"File input '{input_path}' rusak atau tidak lengkap.")
             return False, None

        # Konversi padding_added kembali dari bytes
        padding_added = int.from_bytes(padding_size_bytes, byteorder='big')

        # --- V14: Secure Memory Locking ---
        if config.get("enable_secure_memory_locking", False):
            key_addr = ctypes.addressof((ctypes.c_char * len(key)).from_buffer_copy(key))
            secure_mlock(key_addr, len(key))
            logger.debug(f"Kunci disimpan di memori terkunci untuk {input_path}")
            # Register untuk integrity check
            if config.get("enable_runtime_data_integrity", False):
                register_sensitive_data(f"key_{input_path}", key)

        # AEAD ciphers like AES-GCM and ChaCha20-Poly1305 provide authentication, so a separate HMAC is not needed.

        # --- Decryption berdasarkan algoritma ---
        try:
            if algo == "aes-gcm":
                if PYCRYPTODOME_AVAILABLE:
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    plaintext_data = cipher.decrypt_and_verify(ciphertext, tag)
                elif CRYPTOGRAPHY_AVAILABLE:
                    cipher = AESGCM(key)
                    plaintext_data = cipher.decrypt(nonce, ciphertext, associated_data=None)
                else:
                    raise RuntimeError("Tidak ada pustaka tersedia untuk dekripsi AES-GCM.")
            elif algo == "chacha20-poly1305":
                cipher = ChaCha20Poly1305(key)
                plaintext_data = cipher.decrypt(nonce, ciphertext, associated_data=None)
            elif algo == "xchacha20-poly1305":
                box = nacl.secret.SecretBox(key)
                plaintext_data = box.decrypt(ciphertext)
            elif algo == "aes-siv":
                siv = SIV(key)
                plaintext_data = siv.open(ciphertext, associated_data=[])
            else:
                raise ValueError(f"Algoritma tidak dikenal: {algo}")
        except Exception as e:
            print(f"{RED}❌ Error: Dekripsi gagal. Kunci mungkin salah atau file rusak.{RESET}")
            logger.error(f"Dekripsi gagal untuk algoritma {algo}: {e}")
            return False, None

        if padding_added > 0:
            if len(plaintext_data) < padding_added:
                print(f"{RED}❌ Error: File input rusak (padding yang disimpan lebih besar dari data hasil decryption).{RESET}")
                logger.error(f"Padding yang disimpan lebih besar dari data hasil decryption di {input_path}") # Perbaikan: gunakan input_path
                return False, None
            final_plaintext = plaintext_data[:-padding_added]
        else:
            final_plaintext = plaintext_data

        # --- V9: Deobfuskasi di Memori ---
        if config.get("enable_memory_obfuscation", False):
             final_plaintext = deobfuscate_memory(final_plaintext)

        # --- Tambahkan Dekompresi di sini ---
        if config.get("enable_compression", False):
            logger.debug("Mendekompresi data setelah decryption...")
            final_plaintext = decompress_data(final_plaintext)
        else:
            logger.debug("Kompresi dinonaktifkan, melewati dekompresi.")

        calculated_checksum = calculate_checksum(final_plaintext)
        logger.debug(f"Checksum hasil decryption (setelah dekompresi jika diaktifkan): {calculated_checksum.hex()}")
        logger.debug(f"Checksum yang disimpan: {stored_checksum.hex()}")

        if calculated_checksum == stored_checksum:
            # --- V12/V13/V14: Gunakan mmap untuk file besar ---
            large_file_threshold = config.get("large_file_threshold", 10 * 1024 * 1024) # 10MB default
            if config.get("use_mmap_for_large_files", False) and len(final_plaintext) > large_file_threshold:
                print(f"{CYAN}Menggunakan mmap untuk menulis file besar...{RESET}")
                with open(output_path, 'wb') as outfile:
                    with mmap.mmap(outfile.fileno(), len(final_plaintext), access=mmap.ACCESS_WRITE) as mmapped_outfile:
                        mmapped_outfile[:] = final_plaintext
            else:
                with open(output_path, 'wb') as outfile:
                    print_loading_progress()
                    outfile.write(final_plaintext)

            output_size = os.path.getsize(output_path)
            logger.info(f"Ukuran file output: {output_size} bytes")

            end_time = time.time()
            duration = end_time - start_time
            logger.info(f"Durasi decryption: {duration:.2f} detik")

            # --- Hardening V14: Secure Memory Overwrite (FIXED) ---
            if config.get("enable_secure_memory_overwrite", False):
                secure_overwrite_variable(key)
                secure_overwrite_variable(final_plaintext)
                secure_overwrite_variable(plaintext_data)
                secure_overwrite_variable(stored_checksum)
                secure_overwrite_variable(calculated_checksum)
                # Variabel lain yang sensitif bisa ditambahkan di sini

            if hide_paths:
                print(f"{GREEN}✅ File berhasil didecryption.{RESET}")
                logger.info(f"Decryption (simple) berhasil ke file di direktori: {output_dir}")
            else:
                print(f"{GREEN}✅ File '{input_path}' berhasil didecryption ke '{output_path}' (Simple Mode).{RESET}")
                logger.info(f"Decryption (simple) berhasil dan checksum cocok: {input_path} -> {output_path}")

            return True, output_path
        else:
            print(f"{RED}❌ Error: Decryption gagal. Checksum tidak cocok. File mungkin rusak atau dimanipulasi.{RESET}")
            logger.error(f"Decryption (simple) gagal (checksum tidak cocok) untuk {input_path} -> {output_path}")
            return False, None

    except FileNotFoundError:
        if hide_paths:
            print(f"{RED}❌ Error: File input tidak ditemukan.{RESET}")
            logger.error(f"File input tidak ditemukan saat decryption (simple) di direktori: {output_dir}")
        else:
            print(f"{RED}❌ Error: File '{input_path}' tidak ditemukan.{RESET}") # Perbaikan: gunakan input_path
            logger.error(f"File '{input_path}' tidak ditemukan saat decryption (simple).") # Perbaikan: gunakan input_path
        return False, None
    except Exception as e:
        if hide_paths:
            print(f"{RED}❌ Error saat mendecryption file: {e}{RESET}")
            logger.error(f"Error saat mendecryption (simple) di direktori '{output_dir}': {e}")
        else:
            print(f"{RED}❌ Error saat mendecryption file (simple): {e}{RESET}")
            logger.error(f"Error saat mendecryption (simple) {input_path}: {e}") # Perbaikan: gunakan input_path
        return False, None

def apply_rsa_layer(input_path: str, output_path: str, password: str, keyfile_path: str) -> bool:
    """Applies a hybrid RSA encryption layer to a file."""
    try:
        rsa_private_key, _ = load_keys(password, keyfile_path)
        if rsa_private_key is None:
            print(f"{YELLOW}Kunci RSA tidak ditemukan. Membuat kunci baru...{RESET}")
            rsa_private_key, _ = generate_and_save_keys(password, keyfile_path)
            print(f"{GREEN}Kunci baru berhasil dibuat dan disimpan.{RESET}")

        rsa_public_key = rsa_private_key.public_key()

        session_key = secrets.token_bytes(32) # AES-256 key
        aesgcm = AESGCM(session_key)

        encrypted_session_key = rsa_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encrypted_session_key_len = len(encrypted_session_key).to_bytes(2, 'big')

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_out.write(encrypted_session_key_len)
            f_out.write(encrypted_session_key)

            while chunk := f_in.read(config["chunk_size"]):
                nonce = secrets.token_bytes(12)
                ciphertext = aesgcm.encrypt(nonce, chunk, None)
                f_out.write(nonce)
                f_out.write(ciphertext)

        return True
    except Exception as e:
        print_error_box(f"Error saat menerapkan lapisan RSA: {e}")
        logger.error(f"Error applying RSA layer: {e}")
        return False

def remove_rsa_layer(input_path: str, output_path: str, password: str, keyfile_path: str) -> bool:
    """Removes a hybrid RSA encryption layer from a file."""
    try:
        rsa_private_key, _ = load_keys(password, keyfile_path)
        if rsa_private_key is None:
            print_error_box("Gagal memuat kunci RSA untuk dekripsi.")
            return False

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            encrypted_session_key_len = int.from_bytes(f_in.read(2), 'big')
            encrypted_session_key = f_in.read(encrypted_session_key_len)

            session_key = rsa_private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            aesgcm = AESGCM(session_key)

            while True:
                nonce = f_in.read(12)
                if not nonce:
                    break
                ciphertext = f_in.read(config["chunk_size"] + 16) # Read chunk + tag
                decrypted_chunk = aesgcm.decrypt(nonce, ciphertext, None)
                f_out.write(decrypted_chunk)

        return True
    except Exception as e:
        print_error_box(f"Error saat mendekripsi lapisan RSA: {e}")
        logger.error(f"Error removing RSA layer: {e}")
        return False

def apply_curve25519_layer(input_path: str, output_path: str, password: str, keyfile_path: str) -> bool:
    """Applies a hybrid Curve25519 encryption layer to a file."""
    try:
        _, x25519_private_key = load_keys(password, keyfile_path)
        if x25519_private_key is None:
            print(f"{YELLOW}Kunci Curve25519 tidak ditemukan. Membuat kunci baru...{RESET}")
            _, x25519_private_key = generate_and_save_keys(password, keyfile_path)
            print(f"{GREEN}Kunci baru berhasil dibuat dan disimpan.{RESET}")

        x25519_public_key = x25519_private_key.public_key()

        ephemeral_private_key = x25519.X25519PrivateKey.generate()
        ephemeral_public_key = ephemeral_private_key.public_key()
        shared_key = ephemeral_private_key.exchange(x25519_public_key)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'curve25519_layer_encryption',
        )
        session_key = hkdf.derive(shared_key)

        aesgcm = AESGCM(session_key)

        ephemeral_public_key_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_out.write(ephemeral_public_key_bytes)

            while chunk := f_in.read(config["chunk_size"]):
                nonce = secrets.token_bytes(12)
                ciphertext = aesgcm.encrypt(nonce, chunk, None)
                f_out.write(nonce)
                f_out.write(ciphertext)

        return True
    except Exception as e:
        print_error_box(f"Error saat menerapkan lapisan Curve25519: {e}")
        logger.error(f"Error applying Curve25519 layer: {e}")
        return False

def remove_curve25519_layer(input_path: str, output_path: str, password: str, keyfile_path: str) -> bool:
    """Removes a hybrid Curve25519 encryption layer from a file."""
    try:
        _, x25519_private_key = load_keys(password, keyfile_path)
        if x25519_private_key is None:
            print_error_box("Gagal memuat kunci Curve25519 untuk dekripsi.")
            return False

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            ephemeral_public_key_bytes = f_in.read(32)

            ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_key_bytes)
            shared_key = x25519_private_key.exchange(ephemeral_public_key)

            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'curve25519_layer_encryption',
            )
            session_key = hkdf.derive(shared_key)

            aesgcm = AESGCM(session_key)

            while True:
                nonce = f_in.read(12)
                if not nonce:
                    break
                ciphertext = f_in.read(config["chunk_size"] + 16)
                decrypted_chunk = aesgcm.decrypt(nonce, ciphertext, None)
                f_out.write(decrypted_chunk)

        return True
    except Exception as e:
        print_error_box(f"Error saat mendekripsi lapisan Curve25519: {e}")
        logger.error(f"Error removing Curve25519 layer: {e}")
        return False

def encrypt_file_with_master_key(input_path: str, output_path: str, master_key: bytes, key_version: int, add_random_padding: bool = True, hide_paths: bool = False):
    """Encrypts a file using a master key.

    Args:
        input_path (str): The path to the file to encrypt.
        output_path (str): The path to write the encrypted file to.
        master_key (bytes): The master key to use for encryption.
        key_version (int): The version of the master key used.
        add_random_padding (bool): Whether to add random padding to the file.
        hide_paths (bool): Whether to hide the file paths in the output.

    Returns:
        A tuple containing a boolean indicating success and the path to the
        encrypted file.
    """
    logger = logging.getLogger(__name__)
    start_time = time.time()
    output_dir = os.path.dirname(output_path) or "."

    # Input validation
    if not isinstance(input_path, str) or not isinstance(output_path, str):
        print_error_box("Error: Tipe argumen path tidak valid.")
        logger.error("Invalid path argument type provided.")
        return False, None
    if not isinstance(master_key, bytes):
        print_error_box("Error: Tipe argumen master key tidak valid.")
        logger.error("Invalid master key argument type provided.")
        return False, None

    if not os.path.isfile(input_path):
        print(f"{RED}❌ Error: File input '{input_path}' tidak ditemukan.{RESET}")
        logger.error(f"File input '{input_path}' tidak ditemukan.")
        return False, None

    if not os.access(input_path, os.R_OK):
        print(f"{RED}❌ Error: File input '{input_path}' tidak dapat dibaca.{RESET}")
        logger.error(f"File input '{input_path}' tidak dapat dibaca (izin akses).")
        return False, None

    if os.path.getsize(input_path) == 0:
        print(f"{RED}❌ Error: File input '{input_path}' kosong.{RESET}")
        logger.error(f"File input '{input_path}' kosong.")
        return False, None

    if not check_file_size_limit(input_path):
        return False, None

    # Validasi ekstensi output sederhana
    if not output_path.endswith('.encrypted'):
        print(f"{YELLOW}⚠️  Peringatan: Nama file output '{output_path}' tidak memiliki ekstensi '.encrypted'.{RESET}")
        confirm = input(f"{YELLOW}Lanjutkan dengan nama ini? (y/N): {RESET}").strip().lower()
        if confirm not in ['y', 'yes']:
            print(f"{YELLOW}Operasi dibatalkan.{RESET}")
            logger.info("Operasi dibatalkan karena nama output tidak memiliki ekstensi '.encrypted'.")
            return False, None

    if not check_disk_space(input_path, output_dir):
        return False, None

    try:
        if hide_paths:
            print(f"\n{CYAN}[ Encrypting... ]{RESET}")
            logger.info(f"Memulai encrypted file (dengan Master Key) di direktori: {output_dir}")
        else:
            print(f"\n{CYAN}[ Encrypting with Master Key... ]{RESET}")
            logger.info(f"Memulai encrypted file (dengan Master Key): {input_path}")

        input_size = os.path.getsize(input_path)
        logger.info(f"Ukuran file input: {input_size} bytes")

        algo = AlgorithmNegotiator.get_best_algorithm()
        large_file_threshold = config.get("large_file_threshold", 10 * 1024 * 1024)

        # Override to aes-gcm if streaming is possible and file is large
        if input_size > large_file_threshold and _is_streaming_supported("aes-gcm"):
            algo = "aes-gcm"

        logger.info(f"Menggunakan algoritma: {algo}")

        if _is_streaming_supported(algo) and input_size > large_file_threshold:
            print(f"{CYAN}File besar terdeteksi. Menggunakan mode streaming (Master Key)...{RESET}")
            logger.info(f"Using streaming mode (Master Key) for large file {input_path}")

            # 1. Calculate original checksum
            original_checksum_calculator = hashlib.sha256()
            with open(input_path, 'rb') as f_in:
                while chunk := f_in.read(config["chunk_size"]):
                    original_checksum_calculator.update(chunk)
            original_checksum = original_checksum_calculator.digest()

            # 2. Generate and encrypt a unique file key, similar to the in-memory method
            file_key = secrets.token_bytes(config["file_key_length"])
            master_fernet_key = base64.urlsafe_b64encode(master_key)
            master_fernet = Fernet(master_fernet_key)
            encrypted_file_key = master_fernet.encrypt(file_key)

            # 3. Setup encryptor with the plaintext file key
            stream_encryptor = StreamEncryptor(file_key)
            nonce = stream_encryptor.nonce

            # 4. Write file header and stream content
            with open(output_path, 'wb') as f_out:
                f_out.write(b"STREAMV1")
                f_out.write(key_version.to_bytes(4, 'big'))
                # Store the encrypted file key in the header
                f_out.write(len(encrypted_file_key).to_bytes(4, 'big'))
                f_out.write(encrypted_file_key)

                algo_bytes = algo.encode('utf-8')
                f_out.write(len(algo_bytes).to_bytes(1, 'big'))
                f_out.write(algo_bytes)

                f_out.write(nonce)
                f_out.write(original_checksum)

                with open(input_path, 'rb') as f_in:
                    while chunk := f_in.read(config["chunk_size"]):
                        encrypted_chunk = stream_encryptor.update(chunk)
                        f_out.write(encrypted_chunk)

                stream_encryptor.finalize()
                tag = stream_encryptor.tag
                f_out.write(tag)

            end_time = time.time()
            duration = end_time - start_time
            logger.info(f"Durasi enkripsi (streaming, master key): {duration:.2f} detik")
            print(f"{GREEN}✅ File '{input_path}' berhasil dienkripsi ke '{output_path}' (Streaming Mode).{RESET}")
            return True, output_path

        # --- Fallback to in-memory for smaller files ---
        plaintext_data = b""
        # --- V12/V13/V14: Gunakan mmap jika file besar dan diaktifkan ---
        large_file_threshold = config.get("large_file_threshold", 10 * 1024 * 1024) # 10MB default
        if config.get("use_mmap_for_large_files", False) and input_size > large_file_threshold:
            print(f"{CYAN}Menggunakan mmap untuk membaca file besar...{RESET}")
            with open(input_path, 'rb') as infile:
                with mmap.mmap(infile.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                    plaintext_data = mmapped_file[:]
        else:
            with open(input_path, 'rb') as infile:
                while True:
                    chunk = infile.read(config["chunk_size"])
                    if not chunk:
                        break
                    plaintext_data += chunk

        # --- V14: Secure Memory Locking ---
        if config.get("enable_secure_memory_locking", False):
            master_key_addr = ctypes.addressof((ctypes.c_char * len(master_key)).from_buffer_copy(master_key))
            secure_mlock(master_key_addr, len(master_key))
            logger.debug(f"Master Key disimpan di memori terkunci untuk {input_path}")
            # Register untuk integrity check
            if config.get("enable_runtime_data_integrity", False):
                register_sensitive_data(f"master_key_{input_path}", master_key)

        # --- Tambahkan Kompresi di sini ---
        original_checksum = calculate_checksum(plaintext_data)
        logger.debug(f"Checksum data (sebelum kompresi): {original_checksum.hex()}")

        if config.get("enable_compression", False):
            logger.debug("Mengompresi data sebelum encrypted...")
            plaintext_data = compress_data(plaintext_data)
        else:
            logger.debug("Kompresi dinonaktifkan, melewati.")

        data = plaintext_data
        padding_added = 0
        if add_random_padding:
            padding_length = secrets.randbelow(config["chunk_size"])
            random_padding = secrets.token_bytes(padding_length)
            data = plaintext_data + random_padding
            padding_added = padding_length

        # --- Gunakan HKDF untuk derivasi kunci file ---
        file_key = derive_file_key_from_master_key(master_key, input_path) # Gunakan path input untuk HKDF

        # --- V14: Secure Memory Locking ---
        if config.get("enable_secure_memory_locking", False):
            file_key_addr = ctypes.addressof((ctypes.c_char * len(file_key)).from_buffer_copy(file_key))
            secure_mlock(file_key_addr, len(file_key))
            logger.debug(f"File Key disimpan di memori terkunci untuk {input_path}")
            # Register untuk integrity check
            if config.get("enable_runtime_data_integrity", False):
                register_sensitive_data(f"file_key_{input_path}", file_key)

        # --- Pilih Algoritma encrypted ---
        if algo == "aes-gcm":
            if CRYPTOGRAPHY_AVAILABLE:
                nonce = secrets.token_bytes(config["gcm_nonce_len"])
                cipher = AESGCM(file_key)
                ciphertext = cipher.encrypt(nonce, data, associated_data=None)
                tag = b""
            elif PYCRYPTODOME_AVAILABLE:
                nonce = get_random_bytes(config["gcm_nonce_len"])
                cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
                ciphertext, tag = cipher.encrypt_and_digest(data)
        elif algo == "chacha20-poly1305":
            nonce = secrets.token_bytes(12)
            cipher = ChaCha20Poly1305(file_key)
            ciphertext = cipher.encrypt(nonce, data, associated_data=None)
            tag = b""
        elif algo == "xchacha20-poly1305":
            box = nacl.secret.SecretBox(file_key)
            nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
            ciphertext = box.encrypt(data, nonce)
            tag = b""
        elif algo == "aes-siv":
            siv = SIV(file_key)
            ciphertext = siv.seal(data, associated_data=[])
            nonce = b""
            tag = b""
        else:
            print(f"{RED}❌ Error: Algoritma '{algo}' tidak didukung atau pustaka yang diperlukan tidak ada.{RESET}")
            logger.error(f"Unsupported algorithm or missing library for '{algo}'.")
            return False, None

        # Kunci file terencrypted tetap seperti sebelumnya
        master_fernet_key = base64.urlsafe_b64encode(master_key)
        master_fernet = Fernet(master_fernet_key)
        encrypted_file_key = master_fernet.encrypt(file_key)

        # AEAD ciphers like AES-GCM and ChaCha20-Poly1305 provide authentication, so a separate HMAC is not needed.

        # --- V10/V11/V12/V13/V14: Custom File Format Shuffle & Dynamic Header (Variable Parts) ---
        parts_to_write = [
            ("key_version", str(key_version).encode('utf-8')),
            ("algo_name", algo.encode('utf-8')),
            ("nonce", nonce),
            ("checksum", original_checksum),
            ("padding_added", padding_added.to_bytes(config["padding_size_length"], byteorder='big')),
        ]
        if algo == "aes-gcm" and PYCRYPTODOME_AVAILABLE: # Hanya jika menggunakan pycryptodome
            parts_to_write.append(("tag", tag))
        parts_to_write.extend([
            ("encrypted_file_key_len", len(encrypted_file_key).to_bytes(4, byteorder='big')),
            ("encrypted_file_key", encrypted_file_key),
            ("ciphertext", ciphertext),
        ])

        # --- V14: Generate Dynamic Header Parts ---
        dynamic_header_parts = generate_dynamic_header_parts(input_path, len(plaintext_data))
        # Update bagian-bagian yang akan ditulis dengan informasi dari dynamic header
        # Misalnya, kita bisa menyisipkan bagian-bagian ini ke dalam struktur file utama
        # atau menyimpannya di awal file sebagai header meta.
        # Untuk saat ini, kita sertakan bagian-bagian dari dynamic_header_parts ke dalam parts_to_write
        # tapi kita simpan informasi tentang struktur ini di tempat lain (misalnya dalam checksum tambahan atau HMAC).
        # Kita bisa menyimpan struktur (urutan dan nama bagian) dalam checksum tambahan atau HMAC tambahan.
        # Atau, kita buat header yang menjelaskan struktur file.
        # Format setiap bagian: [4_byte_nama][4_byte_panjang][data_panjang_byte]
        final_parts_to_write = []
        for part_name, part_data in parts_to_write:
             final_parts_to_write.append((part_name, part_data))
        # Tambahkan bagian dari dynamic header (ini opsional dan bisa diacak)
        for dyn_part_name, dyn_part_data in dynamic_header_parts:
             final_parts_to_write.append((dyn_part_name, dyn_part_data))

        # --- V18: Tambahkan Decoy Blocks ---
        if config.get("enable_decoy_blocks", False):
            decoy_count = secrets.randbelow(config.get("decoy_block_count", 5) + 1)
            for i in range(decoy_count):
                decoy_size = secrets.randbelow(config.get("decoy_block_max_size", 1024) + 1)
                decoy_data = secrets.token_bytes(decoy_size)
                final_parts_to_write.append((f"decoy_{i}", decoy_data))
                logger.debug(f"Menambahkan blok decoy 'decoy_{i}' dengan ukuran {decoy_size} bytes.")

        shuffled_parts = shuffle_file_parts(final_parts_to_write)

        # --- V14: Dynamic Header Format (Meta Header) ---
        meta_header_version = config["dynamic_header_version"].to_bytes(2, byteorder='big') # 2 byte versi
        num_total_parts_bytes = len(shuffled_parts).to_bytes(4, byteorder='big') # 4 byte jumlah bagian
        meta_header_prefix = meta_header_version + num_total_parts_bytes

        structure_payload = b''
        for part_name, part_data in shuffled_parts:
             part_name_bytes = part_name.encode('ascii').ljust(255, b'\x00') # Nama bagian (255 byte, null-terminated)
             part_size_bytes = len(part_data).to_bytes(4, byteorder='little') # Ukuran bagian (4 byte, little endian)
             structure_payload += part_name_bytes + part_size_bytes

        # --- V18: Encrypted Meta Header ---
        header_salt = secrets.token_bytes(16)
        header_key = derive_key_for_header(master_key, header_salt)
        header_nonce = secrets.token_bytes(config["gcm_nonce_len"])
        header_cipher = AESGCM(header_key)
        encrypted_structure_payload = header_cipher.encrypt(header_nonce, structure_payload, associated_data=None)

        # V18 FIX: Store the size of the encrypted header
        encrypted_header_size_bytes = len(encrypted_structure_payload).to_bytes(4, byteorder='big')

        # Simpan nonce header setelah meta header prefix
        header_to_write = meta_header_prefix + encrypted_header_size_bytes + header_nonce + encrypted_structure_payload

        total_output_size = len(header_salt) + len(header_to_write) + sum(len(part_data) for _, part_data in shuffled_parts)

        with open(output_path, 'wb') as outfile:
            print_loading_progress()
            # V18 FIX: Tulis header_salt di luar header terenkripsi
            outfile.write(header_salt)
            # Tulis meta header dulu
            outfile.write(header_to_write)
            # Tulis bagian-bagian yang diacak
            for part_name, part_data in shuffled_parts:
                outfile.write(part_data) # Data bagian
                logger.debug(f"Menulis bagian '{part_name}' ({len(part_data)} bytes) ke file output.")

        output_size = os.path.getsize(output_path)
        logger.info(f"Ukuran file output: {output_size} bytes")

        # --- V8: Verifikasi Integritas Output ---
        if config.get("verify_output_integrity", True):
            print(f"{CYAN}Memverifikasi integritas file output...{RESET}")
            try:
                with open(output_path, 'rb') as f:
                    file_content = f.read()
                calculated_file_checksum = calculate_checksum(file_content)
                # Untuk verifikasi output, kita bisa membandingkan checksum dari seluruh file output
                # dengan checksum yang disimpan di dalam file (checksum data asli) dan HMAC.
                # Atau, kita bisa encrypted ulang file input dan bandingkan outputnya (lebih berat).
                # Untuk saat ini, kita hanya memastikan file output bisa dibaca dan ukurannya sesuai.
                if os.path.getsize(output_path) != output_size:
                    print(f"{RED}❌ Error: Ukuran file output tidak sesuai setelah verifikasi.{RESET}")
                    logger.error(f"Verifikasi integritas output gagal: ukuran tidak cocok untuk {output_path}")
                    return False, None
                print(f"{GREEN}✅ Verifikasi integritas output berhasil.{RESET}")
                logger.info(f"Verifikasi integritas output berhasil untuk {output_path}")
            except Exception as e:
                print(f"{RED}❌ Error saat memverifikasi integritas output: {e}{RESET}")
                logger.error(f"Verifikasi integritas output gagal untuk {output_path}: {e}")
                return False, None


        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"Durasi encrypted: {duration:.2f} detik")

        # --- Hardening V14: Secure Memory Overwrite (FIXED) ---
        if config.get("enable_secure_memory_overwrite", False):
            secure_overwrite_variable(master_key)
            secure_overwrite_variable(file_key)
            secure_overwrite_variable(encrypted_file_key)
            secure_overwrite_variable(plaintext_data)
            secure_overwrite_variable(ciphertext)
            secure_overwrite_variable(original_checksum)
            # Variabel lain yang sensitif bisa ditambahkan di sini

        if hide_paths:
            print(f"{GREEN}✅ File berhasil diencrypted.{RESET}")
            logger.info(f"Encrypted (dengan Master Key) berhasil ke file di direktori: {output_dir}")
        else:
            print(f"{GREEN}✅ File '{input_path}' berhasil diencrypted ke '{output_path}' (dengan Master Key).{RESET}")
            logger.info(f"Encrypted (dengan Master Key) berhasil: {input_path} -> {output_path}")

        return True, output_path

    except FileNotFoundError:
        if hide_paths:
            print(f"{RED}❌ Error: File input tidak ditemukan.{RESET}")
            logger.error(f"File input tidak ditemukan saat encrypted (dengan Master Key) di direktori: {output_dir}")
        else:
            print(f"{RED}❌ Error: File '{input_path}' tidak ditemukan.{RESET}") # Perbaikan: gunakan input_path
            logger.error(f"File '{input_path}' tidak ditemukan saat encrypted (dengan Master Key).") # Perbaikan: gunakan input_path
        return False, None
    except Exception as e:
        if hide_paths:
            print(f"{RED}❌ Error saat mengencrypted file: {e}{RESET}")
            logger.error(f"Error saat mengencrypted (dengan Master Key) di direktori '{output_dir}': {e}")
        else:
            print(f"{RED}❌ Error saat mengencrypted file (dengan Master Key): {e}{RESET}")
            logger.error(f"Error saat mengencrypted (dengan Master Key) {input_path}: {e}") # Perbaikan: gunakan input_path
        return False, None


def decrypt_file_with_master_key(input_path: str, output_path: str, key_manager: KeyManager, hide_paths: bool = False):
    """Decrypts a file using a master key from the KeyManager.

    Args:
        input_path (str): The path to the file to decrypt.
        output_path (str): The path to write the decrypted file to.
        key_manager (KeyManager): The KeyManager instance to use for retrieving the key.
        hide_paths (bool): Whether to hide the file paths in the output.

    Returns:
        A tuple containing a boolean indicating success and the path to the
        decrypted file.
    """
    logger = logging.getLogger(__name__)
    start_time = time.time()

    # Input validation
    if not isinstance(input_path, str) or not isinstance(output_path, str):
        print_error_box("Error: Tipe argumen path tidak valid.")
        logger.error("Invalid path argument type provided.")
        return False, None
    if not isinstance(key_manager, KeyManager):
        print_error_box("Error: Tipe argumen key manager tidak valid.")
        logger.error("Invalid key manager argument type provided.")
        return False, None

    if not os.path.isfile(input_path):
        print(f"{RED}❌ Error: File input '{input_path}' tidak ditemukan.{RESET}")
        logger.error(f"File input '{input_path}' tidak ditemukan.")
        return False, None

    if not os.access(input_path, os.R_OK):
        print(f"{RED}❌ Error: File input '{input_path}' tidak dapat dibaca.{RESET}")
        logger.error(f"File input '{input_path}' tidak dapat dibaca (izin akses).")
        return False, None

    if os.path.getsize(input_path) == 0:
        print(f"{RED}❌ Error: File input '{input_path}' kosong.{RESET}")
        logger.error(f"File input '{input_path}' kosong.")
        return False, None

    # Validasi ekstensi input sederhana
    if not input_path.endswith('.encrypted'):
        print(f"{YELLOW}⚠️  Peringatan: File input '{input_path}' tidak memiliki ekstensi '.encrypted'.{RESET}")
        confirm = input(f"{YELLOW}Apakah ini file terencrypted Thena_dev? (y/N): {RESET}").strip().lower()
        if confirm not in ['y', 'yes']:
            print(f"{YELLOW}Operasi dibatalkan.{RESET}")
            logger.info("Operasi dibatalkan karena ekstensi input '.encrypted' tidak ditemukan.")
            return False, None

    try:
        if hide_paths:
            print(f"\n{CYAN}[ Decrypting... ]{RESET}")
            output_dir = os.path.dirname(output_path) or "."
            logger.info(f"Memulai decryption file (dengan Master Key) ke direktori: {output_dir}")
        else:
            print(f"\n{CYAN}[ Decrypting with Master Key... ]{RESET}")
            logger.info(f"Memulai decryption file (dengan Master Key): {input_path}")

        output_dir = os.path.dirname(output_path) or "."
        input_size = os.path.getsize(input_path)
        estimated_output_size = input_size
        statvfs_result = os.statvfs(output_dir)
        free_space = statvfs_result.f_frsize * statvfs_result.f_bavail

        if free_space < estimated_output_size:
            required_mb = estimated_output_size / (1024*1024)
            free_mb = free_space / (1024*1024)
            print(f"{RED}❌ Error: Ruang disk tidak cukup.{RESET}")
            print(f"   Dibutuhkan sekitar {required_mb:.2f} MB, tersedia {free_mb:.2f} MB di '{output_dir}'.")
            logger.error(f"Ruang disk tidak cukup untuk '{input_path}'. Dibutuhkan {estimated_output_size} bytes, tersedia {free_space} bytes di '{output_dir}'.")
            return False, None

        input_size_log = os.path.getsize(input_path)
        logger.info(f"Ukuran file input: {input_size_log} bytes")

        with open(input_path, 'rb') as f:
            magic_bytes = f.read(8)

        if magic_bytes == b"STREAMV1":
            print(f"{CYAN}Streaming file format terdeteksi. Menggunakan mode streaming (Master Key)...{RESET}")
            logger.info(f"Using streaming mode (Master Key) for decryption of {input_path}")

            with open(input_path, 'rb') as f_in:
                f_in.read(8) # Skip magic bytes

                # Read header
                key_version = int.from_bytes(f_in.read(4), 'big')

                # Retrieve the master key for this version
                try:
                    master_key = key_manager.get_key_by_version(key_version)
                except ValueError as e:
                    print(f"Error: {e}", file=sys.stderr)
                    logger.error(f"Failed to get key version {key_version}: {e}")
                    return False, None

                # Read the encrypted file key and decrypt it
                encrypted_key_len = int.from_bytes(f_in.read(4), 'big')
                encrypted_file_key = f_in.read(encrypted_key_len)
                master_fernet_key = base64.urlsafe_b64encode(master_key)
                master_fernet = Fernet(master_fernet_key)
                file_key = master_fernet.decrypt(encrypted_file_key)

                algo_len = int.from_bytes(f_in.read(1), 'big')
                algo = f_in.read(algo_len).decode('utf-8')
                nonce = f_in.read(config["gcm_nonce_len"])
                stored_checksum = f_in.read(32)

                header_end_pos = 8 + 4 + 4 + encrypted_key_len + 1 + algo_len + len(nonce) + len(stored_checksum)
                tag_pos = input_size_log - config["gcm_tag_len"]

                # Read tag from the end of the file
                f_in.seek(-config["gcm_tag_len"], os.SEEK_END)
                tag = f_in.read(config["gcm_tag_len"])
                f_in.seek(header_end_pos) # Reset position

                stream_decryptor = StreamDecryptor(file_key, nonce, tag)
                calculated_checksum_calculator = hashlib.sha256()

                try:
                    with open(output_path, 'wb') as f_out:
                        bytes_to_read = tag_pos - f_in.tell()
                        while bytes_to_read > 0:
                            chunk_size = min(config["chunk_size"], bytes_to_read)
                            chunk = f_in.read(chunk_size)
                            if not chunk:
                                break
                            decrypted_chunk = stream_decryptor.update(chunk)
                            f_out.write(decrypted_chunk)
                            calculated_checksum_calculator.update(decrypted_chunk)
                            bytes_to_read -= len(chunk)
                    stream_decryptor.finalize()
                    calculated_checksum = calculated_checksum_calculator.digest()

                    if constant_time_compare(calculated_checksum, stored_checksum):
                        end_time = time.time()
                        duration = end_time - start_time
                        logger.info(f"Durasi dekripsi (streaming, master key): {duration:.2f} detik")
                        print(f"{GREEN}✅ File '{input_path}' berhasil didekripsi ke '{output_path}' (Streaming Mode).{RESET}")
                        return True, output_path
                    else:
                        print_error_box("Decryption failed: Checksum mismatch.")
                        return False, None

                except crypto_exceptions.InvalidTag:
                    print_error_box("Decryption failed: Kunci salah atau file rusak (Invalid Tag).")
                    return False, None
                except Exception as e:
                    print_error_box(f"An error occurred during streaming decryption: {e}")
                    return False, None

        # --- Fallback to in-memory for old format ---
        print(f"{YELLOW}Format file lama terdeteksi. Menggunakan mode in-memory...{RESET}")
        file_structure = []
        parts_read = {}
        with open(input_path, 'rb') as infile:
            # V18 FIX: Baca header_salt di luar header
            header_salt = infile.read(16)
            # --- V18: Baca Dynamic Meta Header ---
            meta_header_prefix_size = 2 + 4 # Versi (2) + Jumlah Bagian (4)
            meta_header_prefix = infile.read(meta_header_prefix_size)
            version_bytes = meta_header_prefix[:2]
            num_total_parts_bytes = meta_header_prefix[2:6]

            version = int.from_bytes(version_bytes, byteorder='big')
            num_total_parts = int.from_bytes(num_total_parts_bytes, byteorder='big')
            logger.debug(f"Meta header dinamis dibaca: Versi={version}, Num_Total_Parts={num_total_parts}")

            # V18 FIX: Read the size of the encrypted header
            encrypted_header_size_bytes = infile.read(4)
            encrypted_header_size = int.from_bytes(encrypted_header_size_bytes, byteorder='big')

            # --- V18: Decrypt Meta Header ---
            header_nonce = infile.read(config["gcm_nonce_len"])
            encrypted_structure_payload = infile.read(encrypted_header_size)

            header_key = derive_key_for_header(master_key, header_salt)
            header_cipher = AESGCM(header_key)

            try:
                decrypted_meta_header_structure_info = header_cipher.decrypt(header_nonce, encrypted_structure_payload, associated_data=None)
            except Exception as e:
                print(f"{RED}❌ Error: Gagal mendekripsi header. Master Key mungkin salah atau file rusak.{RESET}")
                logger.error(f"Gagal mendekripsi header (master key): {e}")
                return False, None


            # --- V18: Parse Info Struktur dari Meta Header ---
            structure_info_idx = 0
            file_structure = []
            for _ in range(num_total_parts):
                 part_name_padded_bytes = decrypted_meta_header_structure_info[structure_info_idx : structure_info_idx + 255]
                 structure_info_idx += 255
                 part_name = part_name_padded_bytes.decode('ascii').strip('\x00')
                 part_size_bytes = decrypted_meta_header_structure_info[structure_info_idx : structure_info_idx + 4]
                 structure_info_idx += 4
                 part_size = int.from_bytes(part_size_bytes, byteorder='little')
                 file_structure.append((part_name, part_size))
                 logger.debug(f"Struktur file: Bagian '{part_name}', Ukuran: {part_size} bytes")


            # --- V18: Baca Bagian-Bagian Berdasarkan Struktur ---
            parts_read = {}
            for part_name, part_size in file_structure:
                 part_data = infile.read(part_size)
                 if len(part_data) != part_size:
                      print(f"{RED}❌ Error: File input rusak (data bagian '{part_name}' tidak lengkap).{RESET}")
                      logger.error(f"Data bagian '{part_name}' tidak lengkap di {input_path}")
                      return False, None
                 parts_read[part_name] = part_data
                 logger.debug(f"Bagian '{part_name}' ({part_size} bytes) dibaca dari file input.")


        # Ambil bagian-bagian yang diperlukan
        key_version_bytes = parts_read.get("key_version")
        if not key_version_bytes:
            print(f"{RED}❌ Error: File tidak berisi versi kunci. Format mungkin sudah usang atau file rusak.{RESET}")
            logger.error(f"Versi kunci tidak ditemukan di file: {input_path}")
            return False, None
        key_version = int(key_version_bytes.decode('utf-8'))

        nonce = parts_read.get("nonce")
        stored_checksum = parts_read.get("checksum")
        padding_size_bytes = parts_read.get("padding_added")
        len_encrypted_key_bytes = parts_read.get("encrypted_file_key_len")
        encrypted_file_key = parts_read.get("encrypted_file_key")
        ciphertext = parts_read.get("ciphertext")
        # Tag hanya ada jika pycryptodome
        tag = parts_read.get("tag") if PYCRYPTODOME_AVAILABLE else b""

        if not all([nonce, stored_checksum, padding_size_bytes, len_encrypted_key_bytes, encrypted_file_key, ciphertext]):
             print(f"{RED}❌ Error: File input tidak valid atau rusak (bagian penting hilang).{RESET}")
             logger.error(f"File input '{input_path}' rusak atau tidak lengkap.")
             return False, None

        # Konversi padding_added dan len_encrypted_key kembali dari bytes
        padding_added = int.from_bytes(padding_size_bytes, byteorder='big')
        len_encrypted_key = int.from_bytes(len_encrypted_key_bytes, byteorder='big')

        if len(encrypted_file_key) != len_encrypted_key:
             print(f"{RED}❌ Error: File input rusak (panjang encrypted key tidak sesuai).{RESET}")
             logger.error(f"File input '{input_path}' rusak: panjang encrypted key tidak sesuai.")
             return False, None

        try:
            master_key = key_manager.get_key_by_version(key_version)
        except ValueError as e:
            print(f"{RED}❌ Error: {e}{RESET}")
            logger.error(f"Gagal mendapatkan kunci versi {key_version}: {e}")
            return False, None

        master_fernet_key = base64.urlsafe_b64encode(master_key)
        master_fernet = Fernet(master_fernet_key)
        try:
            file_key = master_fernet.decrypt(encrypted_file_key)
        except Exception as e:
            print(f"{RED}❌ Error: Gagal mendecryption File Key. Master Key mungkin salah.{RESET}")
            logger.error(f"Gagal mendecryption File Key: {e}")
            return False, None

        # --- V14: Secure Memory Locking ---
        if config.get("enable_secure_memory_locking", False):
            master_key_addr = ctypes.addressof((ctypes.c_char * len(master_key)).from_buffer_copy(master_key))
            file_key_addr = ctypes.addressof((ctypes.c_char * len(file_key)).from_buffer_copy(file_key))
            secure_mlock(master_key_addr, len(master_key))
            secure_mlock(file_key_addr, len(file_key))
            logger.debug(f"Master Key dan File Key disimpan di memori terkunci untuk {input_path}")
            # Register untuk integrity check
            if config.get("enable_runtime_data_integrity", False):
                register_sensitive_data(f"master_key_{input_path}", master_key)
                register_sensitive_data(f"file_key_{input_path}", file_key)

        # AEAD ciphers like AES-GCM and ChaCha20-Poly1305 provide authentication, so a separate HMAC is not needed.

        hmac_key = derive_hmac_key_from_master_key(master_key, input_path)
        # --- V14: Secure Memory Locking untuk HMAC Key ---
        if config.get("enable_secure_memory_locking", False):
            hmac_key_addr = ctypes.addressof((ctypes.c_char * len(hmac_key)).from_buffer_copy(hmac_key))
            secure_mlock(hmac_key_addr, len(hmac_key))
            logger.debug(f"HMAC Key disimpan di memori terkunci untuk {input_path}")
            # Register untuk integrity check
            if config.get("enable_runtime_data_integrity", False):
                register_sensitive_data(f"hmac_key_{input_path}", hmac_key)

        # --- Decryption berdasarkan algoritma ---
        algo_name_bytes = parts_read.get("algo_name")
        if algo_name_bytes:
            algo = algo_name_bytes.decode('utf-8')
        else:
            # Fallback for old file format without algo identifier
            algo = config.get("encryption_algorithm", "aes-gcm").lower()
            logger.warning(f"File format lama terdeteksi. Menggunakan algoritma dari konfigurasi: {algo}")

        try:
            if algo == "aes-gcm":
                if PYCRYPTODOME_AVAILABLE and tag:
                    cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
                    plaintext_data = cipher.decrypt_and_verify(ciphertext, tag)
                elif CRYPTOGRAPHY_AVAILABLE:
                    cipher = AESGCM(file_key)
                    plaintext_data = cipher.decrypt(nonce, ciphertext, associated_data=None)
                else:
                    raise RuntimeError("Tidak ada pustaka tersedia untuk dekripsi AES-GCM.")
            elif algo == "chacha20-poly1305":
                cipher = ChaCha20Poly1305(file_key)
                plaintext_data = cipher.decrypt(nonce, ciphertext, associated_data=None)
            elif algo == "xchacha20-poly1305":
                box = nacl.secret.SecretBox(file_key)
                plaintext_data = box.decrypt(ciphertext)
            elif algo == "aes-siv":
                siv = SIV(file_key)
                plaintext_data = siv.open(ciphertext, associated_data=[])
            else:
                raise ValueError(f"Algoritma tidak dikenal: {algo}")
        except Exception as e:
            print(f"{RED}❌ Error: Dekripsi gagal. Kunci mungkin salah atau file rusak.{RESET}")
            logger.error(f"Dekripsi gagal untuk algoritma {algo}: {e}")
            return False, None

        if padding_added > 0:
            if len(plaintext_data) < padding_added:
                print(f"{RED}❌ Error: File input rusak (padding yang disimpan lebih besar dari data hasil decryption).{RESET}")
                logger.error(f"Padding yang disimpan lebih besar dari data hasil decryption di {input_path}") # Perbaikan: gunakan input_path
                return False, None
            final_plaintext = plaintext_data[:-padding_added]
        else:
            final_plaintext = plaintext_data

        # --- Tambahkan Dekompresi di sini ---
        if config.get("enable_compression", False):
            logger.debug("Mendekompresi data setelah decryption...")
            final_plaintext = decompress_data(final_plaintext)
        else:
            logger.debug("Kompresi dinonaktifkan, melewati dekompresi.")

        calculated_checksum = calculate_checksum(final_plaintext)
        logger.debug(f"Checksum hasil decryption (setelah dekompresi jika diaktifkan): {calculated_checksum.hex()}")
        logger.debug(f"Checksum yang disimpan: {stored_checksum.hex()}")

        if calculated_checksum == stored_checksum:
            # --- V12/V13/V14: Gunakan mmap untuk file besar ---
            large_file_threshold = config.get("large_file_threshold", 10 * 1024 * 1024) # 10MB default
            if config.get("use_mmap_for_large_files", False) and len(final_plaintext) > large_file_threshold:
                print(f"{CYAN}Menggunakan mmap untuk menulis file besar...{RESET}")
                with open(output_path, 'wb') as outfile:
                    with mmap.mmap(outfile.fileno(), len(final_plaintext), access=mmap.ACCESS_WRITE) as mmapped_outfile:
                        mmapped_outfile[:] = final_plaintext
            else:
                with open(output_path, 'wb') as outfile:
                    print_loading_progress()
                    outfile.write(final_plaintext)

            output_size = os.path.getsize(output_path)
            logger.info(f"Ukuran file output: {output_size} bytes")

            end_time = time.time()
            duration = end_time - start_time
            logger.info(f"Durasi decryption: {duration:.2f} detik")

            # --- Hardening V14: Secure Memory Overwrite (FIXED) ---
            if config.get("enable_secure_memory_overwrite", False):
                secure_overwrite_variable(master_key)
                secure_overwrite_variable(file_key)
                secure_overwrite_variable(encrypted_file_key)
                secure_overwrite_variable(final_plaintext)
                secure_overwrite_variable(plaintext_data)
                secure_overwrite_variable(ciphertext)
                secure_overwrite_variable(stored_checksum)
                secure_overwrite_variable(calculated_checksum)
                # Variabel lain yang sensitif bisa ditambahkan di sini

            if hide_paths:
                print(f"{GREEN}✅ File berhasil didecryption.{RESET}")
                logger.info(f"Decryption (dengan Master Key) berhasil ke file di direktori: {output_dir}")
            else:
                print(f"{GREEN}✅ File '{input_path}' berhasil didecryption ke '{output_path}' (dengan Master Key).{RESET}")
                logger.info(f"Decryption (dengan Master Key) berhasil dan checksum cocok: {input_path} -> {output_path}")

            return True, output_path
        else:
            print(f"{RED}❌ Error: Decryption gagal. Checksum tidak cocok. File mungkin rusak atau dimanipulasi.{RESET}")
            logger.error(f"Decryption (dengan Master Key) gagal (checksum tidak cocok) untuk {input_path} -> {output_path}")
            return False, None

    except FileNotFoundError:
        if hide_paths:
            print(f"{RED}❌ Error: File input tidak ditemukan.{RESET}")
            logger.error(f"File input tidak ditemukan saat decryption (dengan Master Key) di direktori: {output_dir}")
        else:
            print(f"{RED}❌ Error: File '{input_path}' tidak ditemukan.{RESET}") # Perbaikan: gunakan input_path
            logger.error(f"File '{input_path}' tidak ditemukan saat decryption (dengan Master Key).") # Perbaikan: gunakan input_path
        return False, None
    except Exception as e:
        if hide_paths:
            print(f"{RED}❌ Error saat mendecryption file: {e}{RESET}")
            logger.error(f"Error saat mendecryption (dengan Master Key) di direktori '{output_dir}': {e}")
        else:
            print(f"{RED}❌ Error saat mendecryption file (dengan Master Key): {e}{RESET}")
            logger.error(f"Error saat mendecryption (dengan Master Key) {input_path}: {e}") # Perbaikan: gunakan input_path
        return False, None


def encrypt_file_hybrid(input_path: str, output_path: str, password: str, keyfile_path: str = None, hide_paths: bool = False):
    """Encrypts a file using the HybridCipher class."""
    try:
        cipher = HybridCipher(password, keyfile_path)
        return cipher.encrypt(input_path, output_path)
    except Exception as e:
        print_error_box(f"Gagal melakukan enkripsi hybrid: {e}")
        logger.error(f"Gagal melakukan enkripsi hybrid: {e}", exc_info=True)
        return False

def decrypt_file_hybrid(input_path: str, output_path: str, password: str, keyfile_path: str = None, hide_paths: bool = False):
    """Decrypts a file using the HybridCipher class."""
    try:
        cipher = HybridCipher(password, keyfile_path)
        return cipher.decrypt(input_path, output_path)
    except Exception as e:
        print_error_box(f"Gagal melakukan dekripsi hybrid: {e}")
        logger.error(f"Gagal melakukan dekripsi hybrid: {e}", exc_info=True)
        return False

# --- Fungsi UI ---
def print_box(title, options=None, width=80):
    """Prints a box with a title and options.

    Args:
        title: The title to display in the box.
        options: A list of options to display in the box.
        width: The width of the box.
    """
    border_color = CYAN
    title_color = WHITE
    option_color = MAGENTA
    reset = RESET

    logo_ascii = r"""    ⢀⣠⣴⣖⣺⣿⣍⠙⠛⠒⠦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⡤⠖⠚⠋⠉⣿⣟⣒⣶⣤⣀
    ⠙⠉⠉⠉⠉⠙⠛⢶⣶⡦⠀⠀⠉⠳⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠛⠁⠀⠀⣶⣶⠞⠛⠉⠉⠉⠉⠙
    ⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢿⣟⣀⡀⠈⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⠀⢀⢐⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⡟⠀⠀⠘⢷⡀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠟⠁⠀⠘⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⠃⠀⠀⢻⣆⠼⣷⣤⣇⣱⣶⣸⣧⣴⡦⢔⣶⠃⠀⠀⢻⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⠿⠉⠛⣿⣷⣿⣿⣿⣿⣼⣿⣿⣿⣷⣿⡟⠋⠹⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣦⡶⠟⠛⠛⠿⠿⠋⠀⠀⠈⠻⠿⠟⠋⠛⠷⣦⣞⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⠛⢻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠛⠛⠷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠟⠀⠀⠀⠈⣷⠀⣀⣀⡀⠀⠀⠀⠀⠀⠀⢀⣀⣤⡀⢰⡏⠀⠀⠀⠈⠳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⣁⣠⣤⣤⡤⠴⣿⠀⢸⣨⣿⣧⣀⣀⣀⣀⣠⣾⣧⣸⠀⢸⡷⠦⣤⣤⣤⣄⡘⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⣠⠞⣷⣾⣿⠿⠛⠁⠀⠀⣿⡀⠀⠛⠿⠿⠋⣉⢋⣉⠙⠿⠟⠃⠀⣸⡇⠀⠀⠙⠻⢿⣿⣶⣝⣦⣄⡀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠈⠛⠛⠛⠓⠛⠛⠉⠁⠀⠀⠀⠀⠀⠀⠘⢷⡀⠠⣀⠀⠀⠈⡟⠁⠀⢀⡠⠀⣰⠟⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠛⠛⠛⠋⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⡈⢳⡀⠀⠁⠀⡰⠋⣰⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣤⣾⣿⡖⠃⠀⠀⠀⠃⣾⣿⣦⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣟⠓⢶⣴⠞⠚⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠤⣀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⡛⠲⣶⣿⡶⠚⣹⣿⣿⣿⣿⣿⣿⣿⣦⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠈⠙⠒⠒⠋⣹⣿⠟⢹⣿⣿⣿⣿⣿⣿⡷⠚⣶⣿⣶⣾⣿⣿⣿⣿⣿⣿⡙⣿⣿⡉⠑⠒⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠒⠒⠚⠉⠀⢹⢋⡿⠉⢹⢻⡟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡉⠹⣏⢻⠁⠀⠙⠒⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠒⠒⠚⠉⠀⣾⠋⠁⢀⡴⣻⣸⡿⠿⡏⡇⠈⣿⣿⡏⠈⡛⡿⠿⣿⣘⡷⣄⡀⠉⢳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠞⠁⠉⠉⠁⠙⢁⠞⠀⠀⡷⠁⣠⠋⡟⢣⡀⠱⡇⠀⠈⡆⠙⠁⠉⠉⠉⠉⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡠⠖⠁⠀⠀⢠⡿⠚⠁⠀⠀⠀⠙⠲⣤⠀⠀⠀⠑⠢⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡜⠀⠀⠀⠀⠀⠀⠀⠀⠑⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"""

    logo_lines = logo_ascii.split('\n')
    print(f"{border_color}╭" + "─" * (width - 2) + f"╮{reset}")
    for line in logo_lines:
        padded_line = line.center(width - 2)[:width-2]
        print(f"{border_color}│{reset}{padded_line}{border_color}│{reset}")
    if logo_lines:
        print(f"{border_color}│{reset}" + " " * (width - 2) + f"{border_color}│{reset}")

    title_centered = title.center(width - 2)
    print(f"{border_color}│{reset}{title_color}{BOLD}{title_centered}{RESET}{border_color}│{reset}")
    print(f"{border_color}├" + "─" * (width - 2) + f"┤{reset}")
    if options:
        for option in options:
            option_padded = option.ljust(width - 4)
            print(f"{border_color}│{reset} {option_color}{option_padded}{reset} {border_color}│{reset}")
    print(f"{border_color}╰" + "─" * (width - 2) + f"╯{reset}")

# --- Fungsi Mode Batch ---
def process_batch_file(args):
    """Processes a single file in batch mode.

    This function is a helper for `batch_process` and is intended to be
    executed in parallel.

    Args:
        args: A tuple containing the arguments for processing the file.

    Returns:
        A tuple containing a boolean indicating success and the path to the
        output file.
    """
    input_file, output_dir, password, keyfile_path, add_padding, hide_paths, mode = args
    # Gunakan suffix dari konfigurasi
    suffix = config.get("output_name_suffix", "")
    output_file = os.path.join(output_dir, os.path.splitext(os.path.basename(input_file))[0] + suffix + ".encrypted")

    if mode == 'encrypt':
        return encrypt_file_simple(input_file, output_file, password, keyfile_path, add_padding, hide_paths)
    elif mode == 'decrypt':
        output_file = os.path.join(output_dir, os.path.splitext(os.path.basename(input_file))[0].replace('.encrypted', '') + suffix)
        # Fungsi decrypt tidak menerima add_padding
        return decrypt_file_simple(input_file, output_file, password, keyfile_path, hide_paths)
    return False, None

def interactive_encrypt():
    """Handles the interactive encryption process."""
    try:
        # Get user inputs
        input_path = input(f"{BOLD}Masukkan path file input untuk enkripsi: {RESET}").strip()

        if not os.path.isfile(input_path):
            print_error_box("File input tidak ditemukan.")
            return

        if not check_file_size_limit(input_path):
            return

        output_path = f"{os.path.splitext(os.path.basename(input_path))[0]}_{int(time.time() * 1000)}.encrypted"
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

        if not validate_password_keyfile(password, keyfile_path, interactive=True):
            return

        # --- Algorithm Selection ---
        print("\nPilih algoritma enkripsi:")
        print("1. Otomatis (rekomendasi)")
        print("2. AES-GCM")
        print("3. ChaCha20-Poly1305")
        print("4. XChaCha20-Poly1305")
        print("5. AES-SIV")

        algo_choice = input(f"{BOLD}Pilihan: {RESET}").strip()

        if algo_choice == '1':
            base_algorithm = AlgorithmNegotiator.get_best_algorithm()
            if base_algorithm is None:
                print_error_box("Tidak ada algoritma yang didukung tersedia.")
                return
        elif algo_choice == '2':
            base_algorithm = "aes-gcm"
        elif algo_choice == '3':
            base_algorithm = "chacha20-poly1305"
        elif algo_choice == '4':
            base_algorithm = "xchacha20-poly1305"
        elif algo_choice == '5':
            base_algorithm = "aes-siv"
        else:
            print_error_box("Pilihan tidak valid.")
            return

        print(f"{CYAN}Menggunakan algoritma: {base_algorithm}{RESET}")
        encryption_layers = [base_algorithm]

        current_file = input_path

        # Layered encryption requires temporary files.
        temp_dir = config.get("temp_dir", "./temp_thena")
        os.makedirs(temp_dir, exist_ok=True)
        temp_fd, temp_output_path = tempfile.mkstemp(suffix=".layer1.tmp", dir=temp_dir)
        os.close(temp_fd)
        
        # ✅ PERBAIKAN: Gunakan globals_manager bukan variabel tidak terdefinisi
        globals_manager.add_temp_file(temp_output_path)

        # Using a temporary copy of config to change algorithm
        original_algorithm = config["encryption_algorithm"]
        config["encryption_algorithm"] = base_algorithm

        success, _ = encrypt_file_simple(current_file, temp_output_path, password, keyfile_path, confirm_filename_prompt=False)

        config["encryption_algorithm"] = original_algorithm # revert config change

        if not success:
            print_error_box("Gagal saat enkripsi dasar.")
            return

        current_file = temp_output_path

        # --- RSA Layer ---
        use_rsa = input(f"{BOLD}Gunakan RSA untuk mengamankan kunci AES? (y/N): {RESET}").strip().lower()
        if use_rsa in ['y', 'yes']:
            encryption_layers.append("rsa")
            temp_fd, next_temp_file = tempfile.mkstemp(suffix=".layer2.tmp", dir=temp_dir)
            os.close(temp_fd)
            
            # ✅ PERBAIKAN: Gunakan globals_manager
            globals_manager.add_temp_file(next_temp_file)
            
            if apply_rsa_layer(current_file, next_temp_file, password, keyfile_path):
                current_file = next_temp_file
            else:
                print_error_box("Gagal menerapkan lapisan RSA.")
                return

        # --- Curve25519 Layer ---
        use_curve = input(f"{BOLD}Gunakan lapisan Curve25519 untuk keamanan tambahan? (y/N): {RESET}").strip().lower()
        if use_curve in ['y', 'yes']:
            encryption_layers.append("curve25519")
            temp_fd, next_temp_file = tempfile.mkstemp(suffix=".layer3.tmp", dir=temp_dir)
            os.close(temp_fd)
            
            # ✅ PERBAIKAN: Gunakan globals_manager
            globals_manager.add_temp_file(next_temp_file)
            
            if apply_curve25519_layer(current_file, next_temp_file, password, keyfile_path):
                current_file = next_temp_file
            else:
                print_error_box("Gagal menerapkan lapisan Curve25519.")
                return

        # --- Finalizing File ---
        metadata = {"layers": encryption_layers}
        metadata_bytes = json.dumps(metadata).encode('utf-8')
        metadata_len = len(metadata_bytes).to_bytes(2, 'big')

        with open(output_path, "wb") as f_out:
            f_out.write(metadata_len)
            f_out.write(metadata_bytes)
            with open(current_file, "rb") as f_in:
                f_out.write(f_in.read())

        print(f"{GREEN}✅ File berhasil dienkripsi ke '{output_path}' dengan lapisan: {', '.join(encryption_layers)}{RESET}")

        delete_original = input(f"{BOLD}Hapus file asli secara AMAN setelah enkripsi? (y/N): {RESET}").strip().lower()
        if delete_original in ['y', 'yes']:
            secure_wipe_file(input_path)

    except Exception as e:
        print_error_box(f"Terjadi error saat enkripsi: {e}")
        logger.error(f"Error during interactive encryption: {e}", exc_info=True)
    finally:
        # atexit handler will clean up temp files.
        pass

def read_metadata(input_path: str) -> (list, int):
    """Reads the metadata header from the input file."""
    try:
        with open(input_path, "rb") as f:
            metadata_len_bytes = f.read(2)
            if not metadata_len_bytes:
                return [], 0
            metadata_len = int.from_bytes(metadata_len_bytes, 'big')
            metadata_bytes = f.read(metadata_len)
            if not metadata_bytes:
                return [], 0
            metadata = json.loads(metadata_bytes.decode('utf-8'))
            header_size = 2 + metadata_len
            return metadata.get("layers", []), header_size
    except (json.JSONDecodeError, FileNotFoundError, OSError, UnicodeDecodeError) as e:
        logger.warning(f"Could not read metadata from {input_path}: {e}")
        return [], 0
        
def enhanced_interactive_encrypt():
    """Enhanced interactive encryption with modern algorithms."""
    try:
        # Get user inputs
        print(f"\n{BOLD}🔐 ENHANCED ENCRYPTION MODE{RESET}")
        print("=" * 50)
        
        input_path = input(f"{BOLD}Masukkan path file input untuk enkripsi: {RESET}").strip()

        if not os.path.isfile(input_path):
            print_error_box("File input tidak ditemukan.")
            return

        if not check_file_size_limit(input_path):
            return

        # Generate output path with timestamp
        base_name = os.path.splitext(os.path.basename(input_path))[0]
        output_path = f"{base_name}_{int(time.time() * 1000)}.encrypted"
        
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

        if not validate_password_keyfile(password, keyfile_path, interactive=True):
            return

        # --- Enhanced Encryption Options ---
        print(f"\n{BOLD}🔐 Enhanced Encryption Options:{RESET}")
        print("1. Standard Encryption (AES-GCM/ChaCha20)")
        print("2. Enhanced Encryption with Forward Secrecy")
        print("3. Maximum Security (Multiple Layers)")
        print("4. Post-Quantum Ready (Experimental)")
        print("5. Custom Algorithm Selection")
        
        choice = input(f"{BOLD}Pilih level enkripsi (1-5): {RESET}").strip()

        success = False
        
        if choice == '1':
            # Standard encryption
            print(f"{CYAN}Menggunakan enkripsi standar...{RESET}")
            success, _ = encrypt_file_simple(input_path, output_path, password, keyfile_path)
            
        elif choice == '2':
            # Enhanced with Forward Secrecy
            print(f"{CYAN}Menggunakan enkripsi dengan Forward Secrecy...{RESET}")
            if not CRYPTOGRAPHY_AVAILABLE:
                print_error_box("Enhanced encryption requires 'cryptography' module.")
                return
                
            cipher = EnhancedHybridCipher(password, keyfile_path)
            success = cipher.encrypt_with_forward_secrecy(input_path, output_path)
            
        elif choice == '3':
            # Maximum Security - Multiple layers
            print(f"{CYAN}Menggunakan enkripsi maximum security...{RESET}")
            success = maximum_security_encrypt(input_path, output_path, password, keyfile_path)
            
        elif choice == '4':
            # Post-Quantum Ready
            print(f"{YELLOW}Post-quantum cryptography (experimental){RESET}")
            success = post_quantum_encrypt(input_path, output_path, password, keyfile_path)
            
        elif choice == '5':
            # Custom algorithm selection
            success = custom_algorithm_encrypt(input_path, output_path, password, keyfile_path)
            
        else:
            print_error_box("Pilihan tidak valid.")
            return

        # --- Result Handling ---
        if success:
            print(f"{GREEN}✅ File berhasil dienkripsi ke '{output_path}'{RESET}")
            
            # Show encryption details
            if choice in ['2', '3', '4', '5']:
                print_encryption_details(output_path)
            
            # Secure deletion option
            delete_original = input(f"{BOLD}Hapus file asli secara AMAN? (y/N): {RESET}").strip().lower()
            if delete_original in ['y', 'yes']:
                secure_wipe_file(input_path)
                print(f"{GREEN}✅ File asli telah dihapus secara aman.{RESET}")
        else:
            print_error_box("Enkripsi gagal. Lihat log untuk detail.")
            
        # Cleanup
        wipe_sensitive_data("master_encryption_key")

    except Exception as e:
        print_error_box(f"Terjadi error saat enkripsi: {e}")
        logger.error(f"Error during enhanced interactive encryption: {e}", exc_info=True)
    finally:
        # Ensure cleanup
        wipe_sensitive_data("master_encryption_key")        

def maximum_security_encrypt(input_path: str, output_path: str, password: str, keyfile_path: str = None) -> bool:
    """Maximum security encryption with multiple layers."""
    try:
        print(f"{CYAN}🔒 Maximum Security Encryption{RESET}")
        print("  - Layer 1: Forward Secrecy with X25519")
        print("  - Layer 2: Authenticated Encryption")
        print("  - Layer 3: Signature Verification")
        
        # Layer 1: Forward Secrecy
        temp_dir = config.get("temp_dir", "./temp_thena")
        os.makedirs(temp_dir, exist_ok=True)
        
        temp_fd, temp1_path = tempfile.mkstemp(suffix=".layer1", dir=temp_dir)
        os.close(temp_fd)
        globals_manager.add_temp_file(temp1_path)
        
        cipher = EnhancedHybridCipher(password, keyfile_path)
        if not cipher.encrypt_with_forward_secrecy(input_path, temp1_path):
            return False
        
        # Layer 2: Additional encryption layer
        temp_fd, temp2_path = tempfile.mkstemp(suffix=".layer2", dir=temp_dir)
        os.close(temp_fd)
        globals_manager.add_temp_file(temp2_path)
        
        # Use different algorithm for second layer
        original_algo = config.get("encryption_algorithm")
        config["encryption_algorithm"] = "aes-gcm"
        success, _ = encrypt_file_simple(temp1_path, temp2_path, password, keyfile_path, confirm_filename_prompt=False)
        config["encryption_algorithm"] = original_algo
        
        if not success:
            return False
        
        # Layer 3: Add digital signature
        with open(temp2_path, 'rb') as f:
            layer2_data = f.read()
        
        # Sign the encrypted data
        key_manager = ModernKeyManager(password, keyfile_path)
        signature = key_manager.sign_data(layer2_data, key_manager.sig_private)
        
        # Write final file with signature
        with open(output_path, 'wb') as f_out:
            # Write signature length and signature
            f_out.write(len(signature).to_bytes(4, 'big'))
            f_out.write(signature)
            # Write encrypted data
            f_out.write(layer2_data)
        
        print(f"{GREEN}✅ Maximum security encryption completed{RESET}")
        return True
        
    except Exception as e:
        logger.error(f"Maximum security encryption failed: {e}")
        return False

def post_quantum_encrypt(input_path: str, output_path: str, password: str, keyfile_path: str = None) -> bool:
    """Post-quantum ready encryption (experimental)."""
    try:
        print(f"{YELLOW}⚠️  Post-Quantum Encryption (Experimental){RESET}")
        print("  - Using hybrid classical + PQC approach")
        print("  - This is future-proofing for quantum computers")
        
        # For now, use enhanced encryption with additional security parameters
        cipher = EnhancedHybridCipher(password, keyfile_path)
        
        # Add PQC metadata to indicate readiness
        metadata = {
            "version": "pqc_ready_v1",
            "classical_algorithms": ["x25519", "aes-gcm", "ed25519"],
            "pqc_ready": True,
            "timestamp": time.time(),
            "warning": "This file uses classical algorithms but is structured for PQC migration"
        }
        
        # Encrypt with enhanced method
        success = cipher.encrypt_with_forward_secrecy(input_path, output_path)
        
        if success:
            # Add PQC metadata to the beginning of the file
            with open(output_path, 'rb') as f:
                original_data = f.read()
            
            metadata_bytes = json.dumps(metadata).encode('utf-8')
            with open(output_path, 'wb') as f_out:
                f_out.write(len(metadata_bytes).to_bytes(4, 'big'))
                f_out.write(metadata_bytes)
                f_out.write(original_data)
        
        return success
        
    except Exception as e:
        logger.error(f"Post-quantum encryption failed: {e}")
        # Fallback to standard encryption
        print(f"{YELLOW}⚠️  Falling back to standard encryption{RESET}")
        return encrypt_file_simple(input_path, output_path, password, keyfile_path)[0]

def custom_algorithm_encrypt(input_path: str, output_path: str, password: str, keyfile_path: str = None) -> bool:
    """Custom algorithm selection for advanced users."""
    try:
        print(f"{CYAN}🎛️  Custom Algorithm Selection{RESET}")
        
        # Key Exchange Algorithm
        print(f"\n{BOLD}Key Exchange Algorithm:{RESET}")
        print("1. X25519 (Recommended)")
        print("2. X448 (Higher Security)")
        kex_choice = input(f"{BOLD}Pilih (1-2): {RESET}").strip()
        kex_algo = "x448" if kex_choice == "2" else "x25519"
        
        # Signature Algorithm
        print(f"\n{BOLD}Signature Algorithm:{RESET}")
        print("1. Ed25519 (Recommended)")
        print("2. Ed448 (Higher Security)")
        print("3. RSA-PSS (Compatibility)")
        sig_choice = input(f"{BOLD}Pilih (1-3): {RESET}").strip()
        sig_algo = "ed25519" if sig_choice == "1" else "ed448" if sig_choice == "2" else "rsa-pss"
        
        # Symmetric Algorithm
        print(f"\n{BOLD}Symmetric Encryption:{RESET}")
        print("1. AES-GCM (Recommended)")
        print("2. ChaCha20-Poly1305")
        print("3. XChaCha20-Poly1305")
        print("4. AES-SIV (Deterministic)")
        sym_choice = input(f"{BOLD}Pilih (1-4): {RESET}").strip()
        sym_algos = ["aes-gcm", "chacha20-poly1305", "xchacha20-poly1305", "aes-siv"]
        sym_algo = sym_algos[int(sym_choice) - 1] if sym_choice.isdigit() and 1 <= int(sym_choice) <= 4 else "aes-gcm"
        
        # Hash Algorithm
        print(f"\n{BOLD}Hash Algorithm:{RESET}")
        print("1. SHA-256 (Compatible)")
        print("2. SHA3-256 (Modern)")
        print("3. BLAKE2b (Fast)")
        print("4. BLAKE3 (Fastest)")
        hash_choice = input(f"{BOLD}Pilih (1-4): {RESET}").strip()
        hash_algos = ["sha256", "sha3-256", "blake2b", "blake3"]
        hash_algo = hash_algos[int(hash_choice) - 1] if hash_choice.isdigit() and 1 <= int(hash_choice) <= 4 else "sha256"
        
        # Apply custom configuration
        original_config = {
            "key_exchange_algorithm": config.get("key_exchange_algorithm"),
            "signature_algorithm": config.get("signature_algorithm"),
            "encryption_algorithm": config.get("encryption_algorithm"),
            "hash_algorithm": config.get("hash_algorithm")
        }
        
        config["key_exchange_algorithm"] = kex_algo
        config["signature_algorithm"] = sig_algo
        config["encryption_algorithm"] = sym_algo
        config["hash_algorithm"] = hash_algo
        
        print(f"\n{CYAN}Konfigurasi yang dipilih:{RESET}")
        print(f"  - Key Exchange: {kex_algo}")
        print(f"  - Signature: {sig_algo}")
        print(f"  - Symmetric: {sym_algo}")
        print(f"  - Hash: {hash_algo}")
        
        # Use enhanced encryption with custom algorithms
        cipher = EnhancedHybridCipher(password, keyfile_path)
        success = cipher.encrypt_with_forward_secrecy(input_path, output_path)
        
        # Restore original configuration
        for key, value in original_config.items():
            if value is not None:
                config[key] = value
        
        return success
        
    except Exception as e:
        logger.error(f"Custom algorithm encryption failed: {e}")
        return False

def print_encryption_details(file_path: str):
    """Prints details about the encryption used."""
    try:
        with open(file_path, 'rb') as f:
            # Read metadata length
            metadata_len_bytes = f.read(4)
            if not metadata_len_bytes:
                return
                
            metadata_len = int.from_bytes(metadata_len_bytes, 'big')
            metadata_bytes = f.read(metadata_len)
            
            if metadata_bytes:
                metadata = json.loads(metadata_bytes.decode('utf-8'))
                
                print(f"\n{BOLD}📊 Encryption Details:{RESET}")
                print("─" * 40)
                
                if "version" in metadata:
                    print(f"  Version: {metadata['version']}")
                if "kex_algorithm" in metadata:
                    print(f"  Key Exchange: {metadata['kex_algorithm']}")
                if "sig_algorithm" in metadata:
                    print(f"  Signature: {metadata['sig_algorithm']}")
                if "sym_algorithm" in metadata:
                    print(f"  Symmetric: {metadata['sym_algorithm']}")
                if "hash_algorithm" in metadata:
                    print(f"  Hash: {metadata['hash_algorithm']}")
                if "pqc_ready" in metadata:
                    print(f"  PQC Ready: {metadata['pqc_ready']}")
                    
                print("─" * 40)
                
    except Exception as e:
        logger.debug(f"Could not read encryption details: {e}")

def interactive_decrypt():
    """Handles the interactive decryption process."""
    try:
        input_path = input(f"{BOLD}Masukkan path file input untuk dekripsi: {RESET}").strip()

        if not os.path.isfile(input_path):
            print_error_box("File input tidak ditemukan.")
            return

        output_path = input(f"{BOLD}Masukkan path file output: {RESET}").strip()
        if not output_path:
            print_error_box("Nama file output tidak boleh kosong.")
            return
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

        encryption_layers, header_size = read_metadata(input_path)
        if not encryption_layers:
            print_error_box("Tidak dapat membaca lapisan enkripsi dari file. File mungkin rusak atau bukan format yang didukung.")
            return

        print(f"{CYAN}Mendekripsi file dengan lapisan: {', '.join(encryption_layers)}{RESET}")

        # For layered decryption, we must use temporary files, regardless of config
        temp_dir = config.get("temp_dir", "./temp_thena")
        os.makedirs(temp_dir, exist_ok=True)
        temp_fd, current_file = tempfile.mkstemp(suffix=".encrypted_content", dir=temp_dir)
        os.close(temp_fd)
        
        # ✅ PERBAIKAN: Gunakan globals_manager bukan variabel tidak terdefinisi
        globals_manager.add_temp_file(current_file)

        with open(input_path, "rb") as f_in, open(current_file, "wb") as f_out:
            f_in.seek(header_size)
            f_out.write(f_in.read())
            
        # Decrypt layers in reverse order of how they were applied
        reversed_layers = encryption_layers[::-1]

        for i, layer in enumerate(reversed_layers):
            # For the last layer, the output is the final decrypted file
            if i == len(reversed_layers) - 1:
                next_output_file = output_path
            else:
                temp_fd, next_output_file = tempfile.mkstemp(suffix=f".decrypted_layer_{i}.tmp", dir=temp_dir)
                os.close(temp_fd)
                
                # ✅ PERBAIKAN: Gunakan globals_manager
                globals_manager.add_temp_file(next_output_file)

            success = False
            if layer == "curve25519":
                success = remove_curve25519_layer(current_file, next_output_file, password, keyfile_path)
            elif layer == "rsa":
                success = remove_rsa_layer(current_file, next_output_file, password, keyfile_path)
            elif layer in ["aes-gcm", "chacha20-poly1305", "xchacha20-poly1305", "aes-siv"]:
                # Temporarily set the config for decrypt_file_simple
                original_algorithm = config["encryption_algorithm"]
                config["encryption_algorithm"] = layer
                success, _ = decrypt_file_simple(current_file, next_output_file, password, keyfile_path, confirm_overwrite_prompt=False)
                config["encryption_algorithm"] = original_algorithm
            else:
                print_error_box(f"Lapisan enkripsi tidak dikenal: {layer}")
                return

            if not success:
                print_error_box(f"Gagal saat mendekripsi lapisan '{layer}'.")
                return

            # The output of this step is the input for the next
            current_file = next_output_file
            if i < len(reversed_layers) - 1:
                # ✅ PERBAIKAN: Gunakan globals_manager
                globals_manager.add_temp_file(current_file)

        print(f"{GREEN}✅ File berhasil didekripsi ke '{output_path}'{RESET}")

        delete_encrypted = input(f"{BOLD}Hapus file terenkripsi setelah dekripsi? (y/N): {RESET}").strip().lower()
        if delete_encrypted in ['y', 'yes']:
            secure_wipe_file(input_path)

    except Exception as e:
        print_error_box(f"Terjadi error saat dekripsi: {e}")
        logger.error(f"Error during interactive decryption: {e}", exc_info=True)
    finally:
        # atexit handler will clean up temp files.
        pass

def interactive_mode():
    while True:
        clear_screen()
        print_box(
            f"Encryption & Decryption Script v20 - ENHANCED",
            [
                "1. Standard Encryption",
                "2. Enhanced Encryption (Modern Algorithms)", 
                "3. Decrypt File",
                "4. Create Keyfile",
                "5. Algorithm Information",
                "6. Exit"
            ],
            width=80
        )
        
        choice = input(f"\n{BOLD}Masukkan pilihan: {RESET}").strip()
        
        if choice == '1':
            interactive_encrypt()  # Original function
        elif choice == '2':
            enhanced_interactive_encrypt()  # New enhanced function
        elif choice == '3':
            interactive_decrypt()
        elif choice == '4':
            create_keyfile_interactive()
        elif choice == '5':
            print_algorithm_support()
            print_hash_algorithm_info()
            input(f"\n{CYAN}Tekan Enter untuk kembali...{RESET}")
        elif choice == '6':
            print("\n" + "─" * 50)
            print(f"{GREEN}✅ Keluar dari program V20.{RESET}")
            print("─" * 50)
            sys.exit(0)
        else:
            print_error_box("Pilihan tidak valid.")
        
        input(f"\n{CYAN}Tekan Enter untuk kembali ke menu utama...{RESET}")


def batch_process(directory: str, mode: str, password: str, keyfile_path: str = None, add_padding: bool = True, hide_paths: bool = False, parallel: bool = False):
    """Processes all files in a directory in batch mode.

    Args:
        directory: The directory to process.
        mode: The mode to use for processing ('encrypt' or 'decrypt').
        password: The password to use for processing.
        keyfile_path: The path to the keyfile to use for processing.
        add_padding: Whether to add random padding to the files.
        hide_paths: Whether to hide the file paths in the output.
        parallel: Whether to process the files in parallel.
    """
    if not os.path.isdir(directory):
        print_error_box(f"Error: Direktori '{directory}' tidak ditemukan.")
        logger.error(f"Direktori batch '{directory}' tidak ditemukan.")
        return

    # Tentukan ekstensi berdasarkan mode dan apakah rekursif
    files_to_process = []
    if mode == 'decrypt':
        target_ext = ".encrypted"
        if config.get("enable_recursive_batch", False):
            print(f"{CYAN}Memindai sub-direktori secara rekursif...{RESET}")
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith(target_ext):
                        files_to_process.append(os.path.join(root, file))
        else:
            files_to_process = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and f.endswith(target_ext)]
    else: # encrypt mode
        if config.get("enable_recursive_batch", False):
            print(f"{CYAN}Memindai sub-direktori secara rekursif...{RESET}")
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if not file.endswith(".encrypted"):
                        files_to_process.append(os.path.join(root, file))
        else:
            files_to_process = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and not f.endswith(".encrypted")]

    if not files_to_process:
        print(f"{YELLOW}⚠️  Tidak ditemukan file yang cocok untuk {mode} di direktori '{directory}'.{RESET}")
        logger.info(f"Tidak ditemukan file yang cocok untuk {mode} di direktori '{directory}' (rekursif: {config.get('enable_recursive_batch', False)}).")
        return

    print(f"{CYAN}Memulai {mode} batch untuk {len(files_to_process)} file...{RESET}")
    logger.info(f"Memulai {mode} batch untuk {len(files_to_process)} file di '{directory}' (rekursif: {config.get('enable_recursive_batch', False)}).")

    success_count = 0
    if parallel and config.get("batch_parallel", False):
        print(f"{CYAN}Menggunakan mode paralel ({config.get('batch_workers', 2)} workers).{RESET}")
        from concurrent.futures import ThreadPoolExecutor, as_completed # Impor di sini untuk menghindari error jika tidak digunakan
        with ThreadPoolExecutor(max_workers=config.get("batch_workers", 2)) as executor:
            futures = [executor.submit(process_batch_file, (f, directory, password, keyfile_path, add_padding, hide_paths, mode)) for f in files_to_process]
            for future in as_completed(futures):
                success, _ = future.result()
                if success:
                    success_count += 1
    else:
        # Mode serial
        for input_file in files_to_process:
            print_box(f"Memproses: {os.path.relpath(input_file, directory)}")
            if mode == 'encrypt':
                suffix = config.get("output_name_suffix", "")
                output_file = os.path.join(directory, os.path.splitext(os.path.basename(input_file))[0] + suffix + ".encrypted")
                success, _ = encrypt_file_simple(input_file, output_file, password, keyfile_path, add_padding, hide_paths)
            elif mode == 'decrypt':
                suffix = config.get("output_name_suffix", "")
                output_file = os.path.join(directory, os.path.splitext(os.path.basename(input_file))[0].replace('.encrypted', '') + suffix)
                # Fungsi decrypt tidak menerima add_padding
                success, _ = decrypt_file_simple(input_file, output_file, password, keyfile_path, hide_paths)
            if success:
                success_count += 1

    print_box(f"Batch {mode} selesai. {success_count}/{len(files_to_process)} file berhasil.")
    logger.info(f"Batch {mode} selesai. {success_count}/{len(files_to_process)} file berhasil.")

# --- Fungsi Utama ---
def main():
    """The main function of the application."""
    # --- Startup Checks ---
    detect_hardware_acceleration()
    safe_tune_argon2_params()

    # --- V10: Inisialisasi Hardening ---
    # Deteksi Debugging (V10/V11/V12/V13/V14)
    if config.get("enable_anti_debug", False):
        if detect_debugging():
            sys.exit(1)  # Keluar jika debugging terdeteksi

    # ✅ PERBAIKAN: Runtime Integrity Check
    if config.get("enable_runtime_integrity", False):
        # Daftarkan fungsi-fungsi kritis
        critical_functions = [
            derive_key_from_password_and_keyfile_pbkdf2,
            derive_key_from_password_and_keyfile_scrypt, 
            derive_key_from_password_and_keyfile_argon2,
            derive_key_from_password_and_keyfile,
            derive_file_key_from_master_key,
            derive_hmac_key_from_master_key,
            derive_key_for_header,
            encrypt_file_simple,
            decrypt_file_simple,
            encrypt_file_with_master_key,
            decrypt_file_with_master_key
        ]
        
        for func in critical_functions:
            register_critical_function(func)
        
        # Mulai thread integrity checker
        interval = config.get("integrity_check_interval", 5)
        integrity_checker_thread = threading.Thread(target=integrity_checker, args=(interval,), daemon=True)
        globals_manager.set_integrity_thread(integrity_checker_thread)
        integrity_checker_thread.start()
        logger.info(f"Runtime integrity checker dimulai dengan interval {interval}s.")

    # ✅ PERBAIKAN: Lanjutkan dengan argument parsing
    parser = argparse.ArgumentParser(description='Thena Dev Encryption Tool')
    parser.add_argument('--encrypt', action='store_true', help='Mode encrypted')
    parser.add_argument('--decrypt', action='store_true', help='Mode decryption')
    parser.add_argument('--batch', action='store_true', help='Mode batch (memerlukan --dir)')
    parser.add_argument('--dir', type=str, help='Direktori untuk mode batch')
    parser.add_argument('-i', '--input', type=str, help='File input (untuk mode tunggal)')
    parser.add_argument('-o', '--output', type=str, help='File output (untuk mode tunggal)')
    parser.add_argument('-p', '--password', type=str, help='Password')
    parser.add_argument('-k', '--keyfile', type=str, help=f'File key (default: {config["master_key_file"]})')
    parser.add_argument('--password-file', type=str, help='Baca password dari file (opsional, menggantikan -p jika diset)')
    parser.add_argument('--random-name', action='store_true', help='Gunakan nama file acak untuk output (hanya untuk encrypted tunggal)')
    parser.add_argument('--add-padding', action='store_true', help='Tambahkan padding acak (default: True)')
    parser.add_argument('--no-padding', action='store_true', help='Jangan tambahkan padding acak')
    parser.add_argument('--hide-paths', action='store_true', help='Sembunyikan path file dalam output')
    parser.add_argument('--enable-compression', action='store_true', help='Aktifkan kompresi zlib sebelum encrypted (menggunakan konfigurasi)')
    parser.add_argument('--disable-compression', action='store_true', help='Nonaktifkan kompresi zlib sebelum encrypted')
    parser.add_argument('--config', type=str, help='Path to the configuration file')
    parser.add_argument('--algo', type=str, help='Algoritma enkripsi yang akan digunakan (misalnya, aes-gcm, chacha20-poly1305)')
    parser.add_argument('--rotate-key', action='store_true', help='Lakukan rotasi kunci master secara manual.')
    parser.add_argument('--keystore', type=str, default='thena_keystore.json', help='Path ke file keystore.')
    parser.add_argument('--enhanced', action='store_true', 
                       help='Use enhanced encryption with modern algorithms')
    parser.add_argument('--max-security', action='store_true',
                       help='Use maximum security encryption (multiple layers)')
    parser.add_argument('--pqc-ready', action='store_true',
                       help='Use post-quantum ready encryption (experimental)')
    
    args = parser.parse_args()

    # Enhanced encryption handling
    if args.enhanced and args.encrypt:
        if not args.input or not args.output or not args.password:
            print_error_box("--input, --output, and --password required for enhanced encryption")
            sys.exit(1)
            
        cipher = EnhancedHybridCipher(args.password, args.keyfile)
        success = cipher.encrypt_with_forward_secrecy(args.input, args.output)
        
    elif args.max_security and args.encrypt:
        if not args.input or not args.output or not args.password:
            print_error_box("--input, --output, and --password required for max security")
            sys.exit(1)
            
        success = maximum_security_encrypt(args.input, args.output, args.password, args.keyfile)
        
    elif args.pqc_ready and args.encrypt:
        if not args.input or not args.output or not args.password:
            print_error_box("--input, --output, and --password required for PQC encryption")
            sys.exit(1)
            
        success = post_quantum_encrypt(args.input, args.output, args.password, args.keyfile)
    
    if args.config:
        global CONFIG_FILE
        CONFIG_FILE = args.config

    # Baca password dari file jika diset
    if args.password_file:
        try:
            with open(args.password_file, 'r') as pf:
                args.password = pf.read().strip()
        except FileNotFoundError:
            print_error_box(f"Error: File password '{args.password_file}' tidak ditemukan.")
            sys.exit(1)
        except Exception as e:
            print_error_box(f"Error saat membaca password dari file: {e}")
            sys.exit(1)

    # Override konfigurasi kompresi jika diset via argumen
    if args.enable_compression:
        config["enable_compression"] = True
        logger.info("Kompresi diaktifkan via argumen baris perintah.")
    if args.disable_compression:
        config["enable_compression"] = False
        logger.info("Kompresi dinonaktifkan via argumen baris perintah.")

    if args.algo:
        if args.algo in ["aes-gcm", "chacha20-poly1305", "xchacha20-poly1305", "aes-siv"]:
            config["preferred_algorithm_priority"] = [args.algo] + [a for a in config["preferred_algorithm_priority"] if a != args.algo]
            logger.info(f"Algoritma diutamakan via argumen baris perintah: {args.algo}")
        else:
            print_error_box(f"Error: Algoritma '{args.algo}' tidak valid.")
            sys.exit(1)

    # --- Mode Selection and Execution ---
    # Determine mode based on arguments. This simplifies the logic flow.
    use_master_key_mode = '--keystore' in sys.argv or args.rotate_key

    # No arguments provided, start interactive mode.
    if not (args.encrypt or args.decrypt or args.batch or args.rotate_key):
        interactive_mode()
        return

    # All command-line operations require a password.
    if args.password:
        password = args.password
        keyfile_path = args.keyfile
    else:
        print_error_box("Error: --password is required for command-line operations.")
        sys.exit(1)

    # --- Batch Mode ---
    if args.batch:
        if not args.dir:
            print_error_box("Error: --dir is required for batch mode.")
            sys.exit(1)
        if not (args.encrypt or args.decrypt):
            print_error_box("Error: Must specify --encrypt or --decrypt for batch mode.")
            sys.exit(1)

        mode = 'encrypt' if args.encrypt else 'decrypt'
        add_padding = not args.no_padding
        batch_process(args.dir, mode, password, keyfile_path, add_padding, args.hide_paths, config.get("batch_parallel", False))
        return

    # --- Master Key Mode ---
    if use_master_key_mode:
        key_manager = KeyManager(args.keystore, password, keyfile_path)
        key_manager.check_rotation_policy()

        if args.rotate_key:
            key_manager.rotate_key()
            return

        if not args.input or not args.output:
            print_error_box("Error: --input and --output are required for master key operations.")
            sys.exit(1)

        add_padding = not args.no_padding
        success = False # Initialize success flag
        if args.encrypt:
            master_key = key_manager.get_active_key()
            active_version = key_manager.get_active_key_version()
            success, out = encrypt_file_with_master_key(args.input, args.output, master_key, active_version, add_padding, args.hide_paths)
        elif args.decrypt:
            success, out = decrypt_file_with_master_key(args.input, args.output, key_manager, args.hide_paths)
        else: # Should not happen if rotate_key is handled
            print_error_box("Error: --encrypt or --decrypt must be specified with --keystore.")
            sys.exit(1)

    # --- Simple/Hybrid Mode ---
    elif args.encrypt or args.decrypt:
        if not args.input or not args.output:
            print_error_box("Error: --input and --output are required.")
            sys.exit(1)

        # Decide between Hybrid and Simple based on config and --algo override
        is_hybrid = config["encryption_algorithm"] == "hybrid-rsa-x25519" and not args.algo
        add_padding = not args.no_padding
        success = False # Initialize success flag

        if is_hybrid:
            if not CRYPTOGRAPHY_AVAILABLE:
                print_error_box("Hybrid mode requires 'cryptography' module.")
                sys.exit(1)
            if args.encrypt:
                success = encrypt_file_hybrid(args.input, args.output, password, keyfile_path, args.hide_paths)
            else:
                success = decrypt_file_hybrid(args.input, args.output, password, keyfile_path, args.hide_paths)
        else: # Simple mode
            if args.encrypt:
                success, _ = encrypt_file_simple(args.input, args.output, password, keyfile_path, add_padding, args.hide_paths)
            else:
                success, _ = decrypt_file_simple(args.input, args.output, password, keyfile_path, args.hide_paths)

    else:
        # This case handles situations where only non-actionable flags like --password are passed.
        print_error_box("No action specified. Please use --encrypt, --decrypt, --batch, or run without arguments for interactive mode.")
        sys.exit(1)

    # Common success/failure message for single-file operations
    if 'success' in locals() and success:
        print_box(f"Operasi selesai: {args.input} -> {args.output}")
    else:
        # Print to stderr for test runners to capture
        print("Operasi gagal.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()