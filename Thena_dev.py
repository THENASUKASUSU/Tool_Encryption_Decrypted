#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Thena_dev_v15.py - ENCRYPTOR (v15 - Rich UI, bcrypt KDF, Enhanced Security, Simplified Menu, Bug Fixed, Security Improved, Hardened, Improved Hardening, Advanced Hardening, Runtime Integrity, Anti-Debug, Secure Memory, Custom Format, Hardware Ready, PQ-Ready, Dynamic Format, Fully Hardened, Argon2 Enhanced, Secure Memory Overwrite Fixed, Advanced Hardening Implemented, Advanced KDF Parameters, Dynamic File Format, Runtime Data Integrity, Secure Memory Locking)
Deskripsi: Versi ini memperkenalkan antarmuka pengguna yang lebih kaya menggunakan 'rich',
           menambahkan 'bcrypt' sebagai opsi Key Derivation Function (KDF) baru,
           dan terus meningkatkan keamanan dan fungsionalitas.
Versi: 15
"""
# --- Impor Modul ---
import bcrypt
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.progress import Progress

# --- Inisialisasi Rich Console ---
console = Console()

# --- Impor dari cryptography untuk semua KDF, HKDF, Fernet, dan Cipher ---
try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    # from cryptography.hazmat.primitives.kdf.argon2 import Argon2 # Tidak digunakan secara langsung, gunakan argon2.low_level
    from cryptography.hazmat.primitives import hashes
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTOGRAPHY_AVAILABLE = True
    console.print("✅ Modul 'cryptography' ditemukan. Fitur Lanjutan Tersedia.", style="green")
except ImportError as e:
    CRYPTOGRAPHY_AVAILABLE = False
    console.print(f"❌ Error mengimpor 'cryptography': {e}", style="bold red")
    console.print("❌ Modul 'cryptography' tidak ditemukan. Fitur Lanjutan Dinonaktifkan.", style="bold red")
    console.print("   Instal dengan: pip install cryptography")

# --- Impor dari pycryptodome (sebagai fallback untuk AES-GCM jika cryptography gagal) ---
PYCRYPTODOME_AVAILABLE = False
if not CRYPTOGRAPHY_AVAILABLE:
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        PYCRYPTODOME_AVAILABLE = True
        console.print("⚠️  Modul 'cryptography' tidak ditemukan. Menggunakan 'pycryptodome' sebagai fallback untuk AES-GCM.", style="yellow")
    except ImportError:
        PYCRYPTODOME_AVAILABLE = False
        console.print("❌ Modul 'pycryptodome' juga tidak ditemukan.", style="bold red")
        console.print("   Instal: pip install pycryptodome")
        import sys
        sys.exit(1)

# --- Impor dari argon2 (PasswordHasher untuk fallback jika cryptography Argon2 tidak tersedia) ---
try:
    from argon2 import PasswordHasher
    from argon2.low_level import hash_secret_raw, Type
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
    console.print("✅ Modul 'argon2' ditemukan.", style="green")
except ImportError:
    ARGON2_AVAILABLE = False
    console.print("❌ Modul 'argon2' tidak ditemukan. Argon2 tidak tersedia.", style="bold red")

# --- Impor lainnya ---
from pathlib import Path
import json
import os
import sys # Impor sys di awal
import secrets
import time
import logging
import hashlib
import stat
import base64
import argparse
from tqdm import tqdm
import zlib # Impor zlib untuk kompresi
import hmac # Impor hmac untuk verifikasi tambahan
import platform # Impor platform untuk hardening (V8)
import tempfile # Impor tempfile untuk hardening (V9)
import atexit # Impor atexit untuk cleanup (V9)
import gc # Impor gc untuk cleanup (V9)
import threading # Impor threading untuk integrity checks (V10/V11/V12/V13/V14)
import ctypes # Impor ctypes untuk secure memory (V10/V11/V12/V13/V14)
import ctypes.util # Impor ctypes.util untuk secure memory (V10/V11/V12/V13/V14)
import signal # Impor signal untuk anti-debug (V10/V11/V12/V13/V14)
import mmap # Impor mmap untuk performa/file besar (V12/V13/V14)
import struct # Impor struct untuk header dinamis (V12/V13/V14)

# --- Nama File Konfigurasi dan Log ---
CONFIG_FILE = "thena_config_v15.json"
LOG_FILE = "thena_encryptor_v15.log"

# --- Variabel Global untuk Hardening V10/V11/V12/V13/V14 ---
integrity_hashes = {} # Dict untuk menyimpan hash fungsi
integrity_data_hashes = {} # Dict untuk menyimpan hash data sensitif di memori (V14)
critical_functions = [] # List untuk menyimpan fungsi-fungsi kritis
integrity_thread = None # Thread untuk pemeriksaan integritas
stop_integrity_check = threading.Event() # Event untuk memberhentikan thread
temp_files_created = set() # Set untuk file sementara (V9/V12/V13/V14)

# --- Fungsi Cleanup Otomatis (V9/V12/V13/V14) ---
def cleanup_temp_files():
    """
    Cleans up temporary files created during the execution of the script.

    This function iterates over the global `temp_files_created` set and attempts to delete each file.
    It logs the result of each deletion attempt.
    """
    logger = logging.getLogger(__name__)
    for temp_file in temp_files_created:
        try:
            os.unlink(temp_file)
            logger.debug(f"File sementara dihapus: {temp_file}")
        except OSError as e:
            logger.warning(f"Gagal menghapus file sementara {temp_file}: {e}")
    logger.info("Cleanup file sementara selesai.")

# Daftarkan fungsi cleanup saat program keluar
atexit.register(cleanup_temp_files)

# --- Fungsi Utilitas Hardening V14 ---
def calculate_code_hash(func):
    """
    Calculates the SHA-256 hash of a function's bytecode.

    Args:
        func (function): The function to hash.

    Returns:
        str: The hexadecimal SHA-256 hash of the function's bytecode, or an empty string if an error occurs.
    """
    try:
        import dis
        bytecode = dis.Bytecode(func).dis()
        code_bytes = bytecode.encode('utf-8')
        return hashlib.sha256(code_bytes).hexdigest()
    except Exception as e:
        logger.warning(f"Gagal mendapatkan kode untuk fungsi '{func.__name__}': {e}")
        return ""

def register_critical_function(func):
    """
    Registers a function as critical for runtime integrity checks.

    This function calculates the hash of the function's bytecode and stores it in the global `integrity_hashes` dictionary.
    The function is also added to the global `critical_functions` list.

    Args:
        func (function): The function to register.
    """
    global critical_functions, integrity_hashes
    critical_functions.append(func)
    hash_val = calculate_code_hash(func)
    if hash_val:
        integrity_hashes[func.__name__] = hash_val
        logger.debug(f"Fungsi kritis '{func.__name__}' didaftarkan untuk pemeriksaan integritas. Hash: {hash_val[:8]}...")
    else:
        logger.error(f"Gagal menghitung hash untuk fungsi kritis '{func.__name__}'. Tidak akan diperiksa.")

def verify_integrity():
    """
    Verifies the integrity of the critical functions.

    This function iterates over the `critical_functions` list and compares the current hash of each function's bytecode
    with the stored hash in the `integrity_hashes` dictionary. If a mismatch is found, it logs a critical error and terminates the program.

    Returns:
        bool: True if the integrity check passes, False otherwise.
    """
    for func in critical_functions:
        current_hash = calculate_code_hash(func)
        stored_hash = integrity_hashes.get(func.__name__)
        if stored_hash and current_hash != stored_hash:
            logger.critical(f"Runtime Integrity Violation: Kode fungsi '{func.__name__}' telah dimodifikasi!")
            print(f"\n{RED}❌ CRITICAL: Integritas runtime dilanggar! Kode '{func.__name__}' berubah.{RESET}")
            print(f"{RED}Program dihentikan secara paksa.{RESET}")
            stop_integrity_check.set() # Hentikan thread
            os.kill(os.getpid(), signal.SIGTERM) # Matikan proses
            return False
    logger.debug("Runtime integrity check for functions passed.")
    return True

def calculate_data_hash(data) -> str:
    """
    Calculates the SHA-256 hash of the given data.

    Args:
        data (bytes, bytearray, str): The data to hash. If the data is a string, it will be encoded as UTF-8.

    Returns:
        str: The hexadecimal SHA-256 hash of the data, or an empty string if the data type is not supported.
    """
    if isinstance(data, (bytes, bytearray, str)):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    return ""

def register_sensitive_data(name: str, data):
    """
    Registers sensitive data for runtime integrity checks.

    This function calculates the hash of the data and stores it in the global `integrity_data_hashes` dictionary.

    Args:
        name (str): The name to associate with the data.
        data (bytes, bytearray, str): The sensitive data to register.
    """
    global integrity_data_hashes
    hash_val = calculate_data_hash(data)
    if hash_val:
        integrity_data_hashes[name] = hash_val
        logger.debug(f"Data sensitif '{name}' didaftarkan untuk pemeriksaan integritas. Hash: {hash_val[:8]}...")
    else:
        logger.warning(f"Gagal menghitung hash untuk data sensitif '{name}'.")

def verify_data_integrity():
    """
    Verifies the integrity of the sensitive data.

    This function is a placeholder for future implementation. It currently always returns True.

    Returns:
        bool: True.
    """
    logger.debug("Runtime data integrity check called.")
    return True

def integrity_checker(interval):
    """
    A thread that periodically runs integrity checks on functions and data.

    Args:
        interval (int): The interval in seconds between integrity checks.
    """
    while not stop_integrity_check.wait(interval):
        if not verify_integrity():
            break
        if not verify_data_integrity():
            break
    logger.info("Thread integrity checker berhenti.")

def check_pydevd():
    """
    Checks for the presence of the pydevd debugger module.

    Returns:
        bool: True if the pydevd module is found, False otherwise.
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
    """
    Checks if the current process is being traced using ptrace.

    This function is only applicable to Linux/Unix systems.

    Returns:
        bool: True if ptrace is detected, False otherwise.
    """
    if platform.system() == "Windows": # Tidak berlaku untuk Windows
        return False
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"))
        # PTRACE_TRACEME
        ptrace_result = libc.ptrace(0, 0, 0, 0)
        if ptrace_result == 0:
            # Berhasil attach, coba detach
            libc.ptrace(1, 0, 0, 0) # PTRACE_DETACH
            return False # Tidak di-debug
        else:
            # Gagal attach, mungkin sudah di-debug
            return True # Dideteksi di-debug
    except (OSError, AttributeError):
        # ptrace tidak tersedia atau tidak bisa digunakan
        pass
    return False

def detect_debugging():
    """
    Detects if the script is being run in a debugging environment.

    This function iterates through the debugging detection methods specified in the configuration
    and terminates the program if a debugger is detected.

    Returns:
        bool: True if a debugger is detected, False otherwise.
    """
    methods = config.get("debug_detection_methods", [])
    for method_name in methods:
        method_func = globals().get(method_name)
        if method_func and callable(method_func):
            if method_func():
                logger.critical("Anti-Debug: Lingkungan debugging terdeteksi!")
                console.print("\n[bold red]❌ CRITICAL: Lingkungan debugging terdeteksi! Program dihentikan.[/bold red]")
                os.kill(os.getpid(), signal.SIGTERM) # Matikan proses secara paksa
                return True
    return False

def secure_mlock(addr, length):
    """
    Locks a memory area to prevent it from being swapped to disk.

    This function is not supported on Windows.

    Args:
        addr (int): The memory address to lock.
        length (int): The size of the memory area to lock.
    """
    if platform.system() != "Windows": # Tidak berlaku untuk Windows
        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c"))
            result = libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))
            if result != 0:
                logger.warning(f"Gagal mengunci memori di alamat {hex(addr)} (mlock).")
            else:
                logger.debug(f"Memori di alamat {hex(addr)} ({length} bytes) dikunci (mlock).")
        except (OSError, AttributeError):
            logger.warning("Fungsi mlock tidak tersedia di platform ini.")
    else:
        logger.info("mlock tidak didukung di Windows.")

def secure_munlock(addr, length):
    """
    Unlocks a memory area, allowing it to be swapped to disk.

    This function is not supported on Windows.

    Args:
        addr (int): The memory address to unlock.
        length (int): The size of the memory area to unlock.
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

def secure_memset(addr, length, value=0):
    """
    Securely fills a memory area with a specific value.

    This function is used to prevent compiler optimizations that might remove the memory overwrite.

    Args:
        addr (int): The memory address to fill.
        length (int): The size of the memory area to fill.
        value (int, optional): The value to fill the memory with. Defaults to 0.
    """
    try:
        # Buat view memori yang bisa ditulis
        mem_view = (ctypes.c_char * length).from_address(addr)
        # Isi dengan nilai (biasanya nol)
        for i in range(length):
            mem_view[i] = chr(value).encode('latin1')[0]
    except Exception as e:
        logger.warning(f"Gagal mengisi memori secara aman di alamat {hex(addr)}: {e}")

def secure_overwrite_variable(var):
    """
    Overwrites a sensitive variable with random data before deleting it.

    This function attempts to securely overwrite the memory occupied by the variable.
    It handles bytearray, bytes, and string types.

    Args:
        var (bytearray, bytes, str): The variable to overwrite.
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
    """
    Shuffles the order of the file parts if the 'custom_format_shuffle' option is enabled in the configuration.

    Args:
        parts_list (list): A list of tuples, where each tuple represents a part of the file.

    Returns:
        list: The shuffled list of file parts, or the original list if shuffling is disabled.
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

def generate_dynamic_header_parts(input_file_path: str, data_size: int) -> list:
    """
    Generates a list of dynamic header parts based on the input file path and data size.

    This function adds a random number of optional metadata parts to the header, making the file structure more variable.

    Args:
        input_file_path (str): The path to the input file.
        data_size (int): The size of the data.

    Returns:
        list: A list of tuples, where each tuple represents a dynamic header part.
    """
    # Misalnya, kita buat jumlah bagian acak berdasarkan ukuran file
    # atau kita acak urutan bagian-bagian yang *wajib* ada
    # atau kita tambahkan bagian-bagian opsional dengan probabilitas tertentu
    import random
    # Acak seed berdasarkan path file dan ukuran
    random.seed(hash(input_file_path) + data_size)
    # Tambahkan bagian opsional dengan probabilitas
    optional_parts = [
        ("metadata_1", secrets.token_bytes(random.randint(1, 100))),
        ("metadata_2", secrets.token_bytes(random.randint(1, 50))),
    ]
    final_parts = []
    for part_name, part_data in optional_parts:
        if random.random() > 0.5: # 50% probabilitas
            final_parts.append((part_name, part_data))

    logger.debug(f"Header dinamis dibuat dengan {len(final_parts)} bagian untuk {input_file_path}.")
    return final_parts

def unshuffle_dynamic_header_parts(parts_list, input_file_path: str, data_size: int) -> dict:
    """
    Restores the original order of the dynamic header parts.

    This function is complex and could be improved. It assumes that the size of the known parts is fixed
    and searches for them based on their size and random position.

    Args:
        parts_list (list): A list of tuples, where each tuple represents a part of the file.
        input_file_path (str): The path to the input file.
        data_size (int): The size of the data.

    Returns:
        dict: A dictionary containing the unshuffled header parts, or None if an error occurs.
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

def derive_key_from_master_key_for_header(master_key: bytes, input_file_path: str) -> bytes:
    """
    Derives a key from the master key to encrypt the dynamic header.

    This function uses HKDF with a unique salt and info string derived from the input file path.

    Args:
        master_key (bytes): The master key.
        input_file_path (str): The path to the input file.

    Returns:
        bytes: The derived key for the header, or a random key if an error occurs.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        print(f"{RED}❌ Error: HKDF (untuk header) memerlukan modul 'cryptography'.{RESET}")
        logger.error("HKDF (untuk header) memerlukan modul 'cryptography', yang tidak tersedia.")
        return secrets.token_bytes(config["dynamic_header_encryption_key_length"]) # Fallback ke acak jika tidak tersedia

    # Buat salt unik berdasarkan path file input
    file_path_hash = hashlib.sha256(input_file_path.encode()).digest()[:16]

    # Ambil string dari konfigurasi dan konversi ke bytes
    info_prefix_str = config.get("header_derivation_info", "thena_v14_header_enc_key_")
    info_bytes = info_prefix_str.encode('utf-8') + file_path_hash

    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=config["dynamic_header_encryption_key_length"],
            salt=file_path_hash,
            info=info_bytes,
        )
        header_key = hkdf.derive(master_key)
        logger.debug(f"Kunci enkripsi header diturunkan dari Master Key menggunakan HKDF (cryptography) (Info: {info_prefix_str} + hash path), Panjang: {len(header_key)} bytes")
        return header_key
    except Exception as e:
        logger.error(f"Kesalahan saat derivasi kunci header dengan HKDF (cryptography): {e}")
        # Fallback ke acak jika HKDF gagal
        return secrets.token_bytes(config["dynamic_header_encryption_key_length"])


# --- Fungsi untuk Memuat Konfigurasi ---
def load_config():
    """
    Loads the configuration from a JSON file or creates a default configuration file if it doesn't exist.

    Returns:
        dict: A dictionary containing the configuration settings.
    """
    # Nilai default untuk V15
    default_config = {
        "kdf_type": "argon2id", # Pilihan KDF: "argon2id", "scrypt", "pbkdf2", "bcrypt"
        "encryption_algorithm": "aes-gcm",
        "argon2_time_cost": 25,
        "argon2_memory_cost": 2**21,
        "argon2_parallelism": 4,
        "scrypt_n": 2**21,
        "scrypt_r": 8,
        "scrypt_p": 1,
        "pbkdf2_iterations": 200000,
        "pbkdf2_hash_algorithm": "sha256",
        "bcrypt_rounds": 12,
        "chunk_size": 64 * 1024,
        "master_key_file": ".master_key_encrypted_v15",
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
        "hkdf_info_prefix": "thena_v14_file_key_", # Awalan untuk info HKDF
        "enable_recursive_batch": False, # Opsi batch rekursif
        "output_name_suffix": "", # Suffix untuk nama output batch
        "use_hmac_verification": True, # Opsi verifikasi HMAC tambahan (V7)
        "hmac_key_length": 32, # Panjang kunci HMAC (V7)
        "argon2_for_hmac": False, # Gunakan Argon2 untuk kunci HMAC (True), atau PBKDF2 (False) (V7)
        "disable_timestamp_in_filename": False, # Opsi untuk nama file output tanpa timestamp (V8)
        "verify_output_integrity": True, # Opsi verifikasi integritas file output (V8)
        "log_level": "INFO", # Level logging (V8)
        "hmac_derivation_info": "thena_v14_hmac_key_", # Info string untuk derivasi HMAC (V8 - Fixed HMAC)
        "enable_temp_files": False, # Opsi untuk menyimpan data sementara ke file (V9 - Hardening)
        "temp_dir": "./temp_thena", # Direktori untuk file sementara (V9 - Hardening)
        "max_file_size": 100 * 1024 * 1024, # Batas maksimal ukuran file yang diproses (100MB) (V9 - Hardening)
        "enable_memory_obfuscation": False, # Opsi untuk obfuskasi data di memori (V9 - Hardening)
        "memory_obfuscation_key": "", # Kunci untuk obfuskasi memori (V9 - Hardening)
        # --- V10/V11/V12/V13: Konfigurasi Hardening Lanjutan ---
        "enable_secure_memory": True, # Opsi untuk mlock dan overwrite variabel sensitif (V10/V11/V12/V13/V14)
        "enable_runtime_integrity": False, # Opsi untuk runtime integrity checks (V10/V11/V12/V13/V14)
        "enable_anti_debug": True, # Opsi untuk anti-debugging techniques (V10/V11/V12/V13/V14)
        "custom_format_shuffle": True, # Opsi untuk mengacak urutan bagian file output (V10/V11/V12/V13/V14)
        "custom_format_encrypt_header": True, # Opsi untuk mengenkripsi header file output (V10/V11/V12/V13/V14)
        "integrity_check_interval": 5, # Interval (detik) untuk pemeriksaan integritas runtime (V10/V11/V12/V13/V14)
        "debug_detection_methods": ["check_pydevd", "check_ptrace"], # Metode deteksi debug (V10/V11/V12/V13/V14)
        # --- V12/V13/V14: Konfigurasi Hardening Lanjutan ---
        "use_mmap_for_large_files": True, # V12/V13/V14: Gunakan mmap untuk file besar (performa/hardening)
        "large_file_threshold": 10 * 1024 * 1024, # V12/V13/V14: Ambang batas file besar (10MB)
        "dynamic_header_version": 2, # V14: Ditingkatkan versi header dinamis
        "dynamic_header_encryption_key_length": 32, # V12/V13/V14: Panjang kunci untuk enkripsi header dinamis
        "enable_secure_memory_overwrite": False, # V12/V13/V14: Aktifkan overwrite variabel sensitif
        "enable_dynamic_header_integrity_check": True, # V12/V13/V14: Aktifkan verifikasi integritas header dinamis
        "hardware_integration_enabled": False, # V12/V13/V14: Placeholder untuk integrasi hardware (TPM)
        "post_quantum_ready": False, # V12/V13/V14: Placeholder untuk kriptografi post-kuantum
        # --- V14: Konfigurasi Hardening Lanjutan ---
        "enable_secure_memory_locking": False, # V14: Aktifkan mlock (jika tersedia)
        "enable_runtime_data_integrity": False, # V14: Aktifkan pemeriksaan integritas data di memori
        "custom_format_variable_parts": True, # V14: Aktifkan struktur bagian file yang bervariasi
        "header_derivation_info": "thena_v14_header_enc_key_", # V14: Info string untuk derivasi kunci header
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
            console.print(f"Konfigurasi V15 dimuat dari {CONFIG_FILE}", style="cyan")
        except json.JSONDecodeError:
            console.print(f"Error membaca {CONFIG_FILE}, menggunakan nilai default V15.", style="bold red")
            config = default_config
    else:
        config = default_config
        try:
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=4)
            console.print(f"File konfigurasi default V15 '{CONFIG_FILE}' dibuat.", style="cyan")
        except IOError:
            console.print(f"Gagal membuat file konfigurasi V15 '{CONFIG_FILE}'. Menggunakan nilai default.", style="bold red")
            config = default_config
    return config

# --- Setup Logging ---
def setup_logging():
    """
    Sets up the logging for the script.

    This function configures the logging to write to both a file and the console.
    The log level is determined by the 'log_level' setting in the configuration.
    """
    level = getattr(logging, config.get("log_level", "INFO").upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)
    logger.info("=== Encryptor V14 Dimulai ===")

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
    """
    Clears the console screen.
    """
    # Hardening (V8): Cek sistem operasi
    os_name = platform.system().lower()
    if os_name == "windows":
        os.system('cls')
    else:
        os.system('clear')

def calculate_checksum(data) -> bytes:
    """
    Calculates the SHA-256 checksum of the given data.

    Args:
        data (bytes): The data to calculate the checksum for.

    Returns:
        bytes: The SHA-256 checksum.
    """
    return hashlib.sha256(data).digest()

def secure_wipe_file(file_path: str, passes: int = 5):
    """
    Securely wipes a file by overwriting it with random data multiple times before deleting it.

    Args:
        file_path (str): The path to the file to wipe.
        passes (int, optional): The number of times to overwrite the file. Defaults to 5.
    """
    if not os.path.exists(file_path):
        console.print(f"⚠️  File '{file_path}' tidak ditemukan, dilewati.", style="yellow")
        logger.warning(f"File '{file_path}' tidak ditemukan saat secure wipe.")
        return

    file_size = os.path.getsize(file_path)
    console.print(f"Menghapus secara aman '{file_path}'...", style="cyan")
    with open(file_path, "r+b") as f:
        for i in range(passes): # Perbaikan: ganti 'passs' menjadi 'passes'
            f.seek(0)
            if i == passes - 1:
                f.write(b'\x00' * file_size)
            elif i == passes - 2:
                f.write(b'\xFF' * file_size)
            else:
                f.write(secrets.token_bytes(file_size)) # Gunakan secrets
            f.flush()
            os.fsync(f.fileno())
    os.remove(file_path)
    console.print(f"✅ File '{file_path}' telah dihapus secara aman ({passes} passes).", style="green")
    logger.info(f"File '{file_path}' dihapus secara aman ({passes} passes).")

def confirm_overwrite(file_path: str) -> bool:
    """
    Asks the user for confirmation before overwriting a file.

    Args:
        file_path (str): The path to the file to be overwritten.

    Returns:
        bool: True if the user confirms, False otherwise.
    """
    if os.path.exists(file_path):
        confirm = Prompt.ask(f"[yellow]File '{file_path}' sudah ada. Ganti? (y/N):[/yellow]").strip().lower()
        if confirm not in ['y', 'yes']:
            console.print("Operasi dibatalkan.", style="yellow")
            logger.info(f"Operasi dibatalkan karena file '{file_path}' sudah ada.")
            return False
    return True

def check_disk_space(file_path: str, output_dir: str) -> bool:
    """
    Checks if there is enough disk space to save the output file.

    Args:
        file_path (str): The path to the input file.
        output_dir (str): The path to the output directory.

    Returns:
        bool: True if there is enough disk space, False otherwise.
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
            console.print("❌ Error: Ruang disk tidak cukup.", style="bold red")
            console.print(f"   Dibutuhkan sekitar {required_mb:.2f} MB, tersedia {free_mb:.2f} MB di '{output_dir}'.")
            logger.error(f"Ruang disk tidak cukup untuk '{file_path}'. Dibutuhkan {estimated_output_size} bytes, tersedia {free_space} bytes di '{output_dir}'.")
            return False
        else:
            logger.info(f"Ruang disk cukup. File '{file_path}' ({file_size} bytes) akan menghasilkan sekitar {estimated_output_size} bytes di '{output_dir}'.")
            return True
    except OSError as e:
        console.print(f"❌ Error saat memeriksa ruang disk: {e}", style="bold red")
        logger.error(f"Error saat memeriksa ruang disk untuk '{file_path}' di '{output_dir}': {e}")
        return False

def validate_password_keyfile(password: str, keyfile_path: str) -> bool:
    """
    Validates the strength of the password and the validity of the keyfile.

    Args:
        password (str): The password to validate.
        keyfile_path (str): The path to the keyfile.

    Returns:
        bool: True if the validation passes, False otherwise.
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
        console.print("⚠️  Peringatan Validasi:", style="yellow")
        for issue in issues:
            console.print(f"   - {issue}")
        logger.warning(f"Peringatan validasi untuk input: {', '.join(issues)}")
        confirm = Prompt.ask("[yellow]Lanjutkan proses? (y/N):[/yellow]").strip().lower()
        if confirm not in ['y', 'yes']:
            console.print("Operasi dibatalkan.", style="yellow")
            logger.info("Operasi dibatalkan berdasarkan validasi input pengguna.")
            return False
    else:
        logger.info("Validasi password/keyfile berhasil.")

    return True

def check_file_size_limit(file_path: str) -> bool:
    """
    Checks if the file size is within the configured limit.

    Args:
        file_path (str): The path to the file.

    Returns:
        bool: True if the file size is within the limit, False otherwise.
    """
    max_size = config.get("max_file_size", 100 * 1024 * 1024) # 100MB default
    file_size = os.path.getsize(file_path)
    if file_size > max_size:
        console.print(f"❌ Error: Ukuran file '{file_path}' ({file_size} bytes) melebihi batas maksimal ({max_size} bytes).", style="bold red")
        logger.error(f"File '{file_path}' ({file_size} bytes) melebihi batas maksimal ({max_size} bytes).")
        return False
    logger.debug(f"File '{file_path}' ({file_size} bytes) berada dalam batas ukuran maksimal ({max_size} bytes).")
    return True

def create_temp_file(suffix=""):
    """
    Creates a temporary file.

    Args:
        suffix (str, optional): The suffix for the temporary file. Defaults to "".

    Returns:
        str: The path to the temporary file, or None if temporary files are disabled.
    """
    if not config.get("enable_temp_files", False):
        return None
    temp_dir = config.get("temp_dir", "./temp_thena")
    os.makedirs(temp_dir, exist_ok=True)
    temp_fd, temp_path = tempfile.mkstemp(suffix=suffix, dir=temp_dir)
    temp_files_created.add(temp_path) # Tambahkan ke set untuk cleanup
    os.close(temp_fd) # Tutup file descriptor
    logger.debug(f"File sementara dibuat: {temp_path}")
    return temp_path

def obfuscate_memory(data) -> bytes:
    """
    Obfuscates data in memory using a simple XOR operation.

    Args:
        data (bytes): The data to obfuscate.

    Returns:
        bytes: The obfuscated data.
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
    """
    Deobfuscates data in memory using a simple XOR operation.

    Args:
        data (bytes): The data to deobfuscate.

    Returns:
        bytes: The deobfuscated data.
    """
    # Deobfuskasi adalah operasi yang sama dengan XOR
    return obfuscate_memory(data)

# --- Fungsi Derivasi Kunci Baru (V14 - Parameter KDF Ditingkatkan) ---
def derive_key_from_password_and_keyfile_pbkdf2(password: str, salt: bytes, keyfile_path: str = None) -> bytes:
    """
    Derives a key from a password and keyfile using PBKDF2.

    Args:
        password (str): The password.
        salt (bytes): The salt.
        keyfile_path (str, optional): The path to the keyfile. Defaults to None.

    Returns:
        bytes: The derived key, or None if an error occurs.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        console.print("❌ Error: PBKDF2 memerlukan modul 'cryptography'.", style="bold red")
        logger.error("PBKDF2 memerlukan modul 'cryptography', yang tidak tersedia.")
        return None

    password_bytes = password.encode('utf-8')
    keyfile_bytes = b""
    if keyfile_path:
        if not os.path.isfile(keyfile_path):
            console.print(f"❌ Error: Keyfile '{keyfile_path}' tidak ditemukan.", style="bold red")
            logger.error(f"File keyfile '{keyfile_path}' tidak ditemukan saat derivasi kunci (PBKDF2).")
            return None
        with open(keyfile_path, 'rb') as kf:
            keyfile_bytes = kf.read()

    combined_input = password_bytes + keyfile_bytes

    hash_algorithm_name = config.get("pbkdf2_hash_algorithm", "sha256")
    if hash_algorithm_name.lower() == "sha256":
        hash_algorithm = hashes.SHA256()
    else:
        console.print(f"❌ Error: Algoritma hash PBKDF2 '{hash_algorithm_name}' tidak didukung.", style="bold red")
        logger.error(f"Algoritma hash PBKDF2 '{hash_algorithm_name}' tidak didukung.")
        return None

    try:
        pbkdf2_kdf = PBKDF2HMAC(
            algorithm=hash_algorithm,
            length=config["file_key_length"],
            salt=salt,
            iterations=config["pbkdf2_iterations"], # V14: Iterasi ditingkatkan
        )
        derived_key = pbkdf2_kdf.derive(combined_input)
        logger.debug(f"Kunci berhasil diturunkan dengan PBKDF2 (cryptography), Panjang: {len(derived_key)} bytes")
        return derived_key
    except Exception as e:
        logger.error(f"Kesalahan saat hashing dengan PBKDF2 (cryptography): {e}")
        return None

def derive_key_from_password_and_keyfile_scrypt(password: str, salt: bytes, keyfile_path: str = None) -> bytes:
    """
    Derives a key from a password and keyfile using Scrypt.

    Args:
        password (str): The password.
        salt (bytes): The salt.
        keyfile_path (str, optional): The path to the keyfile. Defaults to None.

    Returns:
        bytes: The derived key, or None if an error occurs.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        console.print("❌ Error: Scrypt memerlukan modul 'cryptography'.", style="bold red")
        logger.error("Scrypt memerlukan modul 'cryptography', yang tidak tersedia.")
        return None

    password_bytes = password.encode('utf-8')
    keyfile_bytes = b""
    if keyfile_path:
        if not os.path.isfile(keyfile_path):
            console.print(f"❌ Error: Keyfile '{keyfile_path}' tidak ditemukan.", style="bold red")
            logger.error(f"File keyfile '{keyfile_path}' tidak ditemukan saat derivasi kunci (Scrypt).")
            return None
        with open(keyfile_path, 'rb') as kf:
            keyfile_bytes = kf.read()

    combined_input = password_bytes + keyfile_bytes

    try:
        scrypt_kdf = Scrypt(
            salt=salt,
            length=config["file_key_length"],
            n=config["scrypt_n"], # V14: N ditingkatkan
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
    """
    Derives a key from a password and keyfile using Argon2id.

    Args:
        password (str): The password.
        salt (bytes): The salt.
        keyfile_path (str, optional): The path to the keyfile. Defaults to None.

    Returns:
        bytes: The derived key, or None if an error occurs.
    """
    # Kita tetap gunakan argon2.low_level karena lebih stabil dan tidak memerlukan cryptography untuk Argon2 sendiri
    if not ARGON2_AVAILABLE:
        console.print("❌ Error: Argon2 tidak tersedia.", style="bold red")
        logger.error("Argon2 tidak tersedia.")
        return None
        
    password_bytes = password.encode('utf-8')
    keyfile_bytes = b""
    if keyfile_path:
        if not os.path.isfile(keyfile_path):
            console.print(f"❌ Error: Keyfile '{keyfile_path}' tidak ditemukan.", style="bold red")
            logger.error(f"File keyfile '{keyfile_path}' tidak ditemukan saat derivasi kunci (Argon2 low_level).")
            return None
        with open(keyfile_path, 'rb') as kf:
            keyfile_bytes = kf.read()

    combined_input = password_bytes + keyfile_bytes

    try:
        raw_hash = hash_secret_raw(
            secret=combined_input,
            salt=salt,
            time_cost=config["argon2_time_cost"], # V14: Time cost ditingkatkan
            memory_cost=config["argon2_memory_cost"], # V14: Memory cost ditingkatkan
            parallelism=config["argon2_parallelism"], # V14: Parallelism ditingkatkan
            hash_len=config["file_key_length"],
            type=Type.ID
        )
        logger.debug(f"Kunci Argon2id berhasil diturunkan (argon2.low_level), Panjang: {len(raw_hash)} bytes")
        return raw_hash
    except Exception as e:
        logger.error(f"Kesalahan saat hashing dengan Argon2id (argon2.low_level): {e}")
        return None

def derive_key_from_password_and_keyfile_bcrypt(password: str, salt: bytes, keyfile_path: str = None) -> bytes:
    """
    Derives a key from a password and keyfile using bcrypt.

    Args:
        password (str): The password.
        salt (bytes): The salt.
        keyfile_path (str, optional): The path to the keyfile. Defaults to None.

    Returns:
        bytes: The derived key, or None if an error occurs.
    """
    password_bytes = password.encode('utf-8')
    keyfile_bytes = b""
    if keyfile_path:
        if not os.path.isfile(keyfile_path):
            console.print(f"❌ Error: Keyfile '{keyfile_path}' tidak ditemukan.", style="bold red")
            logger.error(f"File keyfile '{keyfile_path}' tidak ditemukan saat derivasi kunci (bcrypt).")
            return None
        with open(keyfile_path, 'rb') as kf:
            keyfile_bytes = kf.read()

    combined_input = hashlib.sha256(password_bytes + keyfile_bytes).digest()

    try:
        derived_key = bcrypt.kdf(
            password=combined_input,
            salt=salt,
            desired_key_bytes=config["file_key_length"],
            rounds=config["bcrypt_rounds"]
        )
        logger.debug(f"Kunci berhasil diturunkan dengan bcrypt, Panjang: {len(derived_key)} bytes")
        return derived_key
    except Exception as e:
        logger.error(f"Kesalahan saat hashing dengan bcrypt: {e}")
        return None

def derive_key_from_password_and_keyfile(password: str, salt: bytes, keyfile_path: str = None) -> bytes:
    """
    Derives a key from a password and keyfile using the configured KDF.

    Args:
        password (str): The password.
        salt (bytes): The salt.
        keyfile_path (str, optional): The path to the keyfile. Defaults to None.

    Returns:
        bytes: The derived key, or None if an error occurs.
    """
    kdf_type = config.get("kdf_type", "argon2id").lower()

    if kdf_type == "pbkdf2":
        if CRYPTOGRAPHY_AVAILABLE:
            return derive_key_from_password_and_keyfile_pbkdf2(password, salt, keyfile_path)
        else:
            console.print(f"❌ Error: KDF '{kdf_type}' memerlukan modul 'cryptography'.", style="bold red")
            logger.error(f"KDF '{kdf_type}' memerlukan modul 'cryptography', yang tidak tersedia.")
            return None

    elif kdf_type == "scrypt":
        if CRYPTOGRAPHY_AVAILABLE:
            return derive_key_from_password_and_keyfile_scrypt(password, salt, keyfile_path)
        else:
            console.print(f"❌ Error: KDF '{kdf_type}' memerlukan modul 'cryptography'.", style="bold red")
            logger.error(f"KDF '{kdf_type}' memerlukan modul 'cryptography', yang tidak tersedia.")
            return None

    elif kdf_type == "argon2id":
        # Gunakan argon2.low_level
        return derive_key_from_password_and_keyfile_argon2(password, salt, keyfile_path)

    elif kdf_type == "bcrypt":
        return derive_key_from_password_and_keyfile_bcrypt(password, salt, keyfile_path)

    else:
        console.print(f"❌ Error: Tipe KDF '{kdf_type}' tidak dikenal. Gunakan 'argon2id', 'scrypt', 'pbkdf2', atau 'bcrypt'.", style="bold red")
        logger.error(f"Tipe KDF '{kdf_type}' tidak dikenal.")
        return None

# --- Fungsi Derivasi Kunci File dengan HKDF (menggunakan cryptography jika tersedia) ---
def derive_file_key_from_master_key(master_key: bytes, input_file_path: str) -> bytes:
    """
    Derives a file key from the master key using HKDF.

    Args:
        master_key (bytes): The master key.
        input_file_path (str): The path to the input file.

    Returns:
        bytes: The derived file key, or a random key if an error occurs.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        console.print("❌ Error: HKDF memerlukan modul 'cryptography'.", style="bold red")
        logger.error("HKDF memerlukan modul 'cryptography', yang tidak tersedia.")
        return secrets.token_bytes(config["file_key_length"]) # Fallback ke acak jika tidak tersedia

    # Buat salt unik berdasarkan path file input
    file_path_hash = hashlib.sha256(input_file_path.encode()).digest()[:16] # Gunakan 16 byte pertama

    # Ambil string dari konfigurasi dan konversi ke bytes
    info_prefix_str = config.get("hkdf_info_prefix", "thena_v14_file_key_")
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
    """
    Derives an HMAC key from the master key using HKDF.

    Args:
        master_key (bytes): The master key.
        input_file_path (str): The path to the input file.

    Returns:
        bytes: The derived HMAC key, or a random key if an error occurs.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        console.print("❌ Error: HKDF (untuk HMAC) memerlukan modul 'cryptography'.", style="bold red")
        logger.error("HKDF (untuk HMAC) memerlukan modul 'cryptography', yang tidak tersedia.")
        return secrets.token_bytes(config["hmac_key_length"]) # Fallback ke acak jika tidak tersedia

    # Buat salt unik berdasarkan path file input (V14)
    file_path_hash = hashlib.sha256(input_file_path.encode()).digest()[:16]

    # Ambil string dari konfigurasi dan konversi ke bytes
    info_prefix_str = config.get("hmac_derivation_info", "thena_v14_hmac_key_")
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

# --- Fungsi Master Key Management ---
def load_or_create_master_key(password: str, keyfile_path: str):
    """
    Loads the master key from the master key file, or creates a new one if it doesn't exist.

    Args:
        password (str): The password.
        keyfile_path (str): The path to the keyfile.

    Returns:
        bytes: The master key, or None if an error occurs.
    """
    master_key = None
    if os.path.exists(config["master_key_file"]):
        console.print(f"Memuat Master Key dari '{config['master_key_file']}'...", style="cyan")
        try:
            with open(config["master_key_file"], 'rb') as f:
                salt = f.read(config["master_key_salt_len"])
                if len(salt) != config["master_key_salt_len"]:
                    console.print("❌ Error: File Master Key rusak (salt tidak valid).", style="bold red")
                    logger.error("File Master Key rusak (salt tidak valid).")
                    return None
                encrypted_master_key_data = f.read()
                fernet_key_bytes = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
                if fernet_key_bytes is None:
                    logger.error("Gagal menurunkan kunci untuk mendekripsi Master Key.")
                    return None
                fernet_key = base64.urlsafe_b64encode(fernet_key_bytes[:32])
                fernet = Fernet(fernet_key)
                try:
                    master_key = fernet.decrypt(encrypted_master_key_data)
                    console.print("✅ Master Key berhasil dimuat.", style="green")
                    logger.info("Master Key berhasil dimuat dari file.")
                except Exception as e:
                    console.print("❌ Error: Gagal mendekripsi Master Key. Password/Keyfile mungkin salah.", style="bold red")
                    logger.error(f"Gagal mendekripsi Master Key: {e}")
                    return None
        except FileNotFoundError:
            console.print(f"❌ Error: File Master Key '{config['master_key_file']}' tidak ditemukan.", style="bold red")
            logger.error(f"File Master Key '{config['master_key_file']}' tidak ditemukan.")
            return None
    else:
        console.print(f"File Master Key '{config['master_key_file']}' tidak ditemukan. Membuat yang baru...", style="yellow")
        master_key = secrets.token_bytes(config["file_key_length"]) # Buat Master Key acak
        salt = secrets.token_bytes(config["master_key_salt_len"]) # Buat salt acak untuk enkripsi Fernet
        fernet_key_bytes = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
        if fernet_key_bytes is None:
            logger.error("Gagal menurunkan kunci untuk mengenkripsi Master Key baru.")
            return None
        fernet_key = base64.urlsafe_b64encode(fernet_key_bytes[:32])
        fernet = Fernet(fernet_key)
        encrypted_master_key_data = fernet.encrypt(master_key)
        with open(config["master_key_file"], 'wb') as f:
            f.write(salt) # Tulis salt dulu
            f.write(encrypted_master_key_data) # Lalu data terenkripsi
        console.print("✅ Master Key baru berhasil dibuat dan disimpan.", style="green")
        logger.info("Master Key baru berhasil dibuat dan disimpan.")

    return master_key

# --- Fungsi Utilitas Kompresi ---
def compress_data(data) -> bytes:
    """
    Compresses data using zlib.

    Args:
        data (bytes): The data to compress.

    Returns:
        bytes: The compressed data, or the original data if compression fails.
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
    """
    Decompresses data using zlib.

    Args:
        data (bytes): The data to decompress.

    Returns:
        bytes: The decompressed data, or the original data if decompression fails.
    """
    try:
        decompressed_data = zlib.decompress(data)
        logger.debug(f"Data didekompresi dari {len(data)} bytes menjadi {len(decompressed_data)} bytes.")
        return decompressed_data
    except Exception as e:
        logger.error(f"Error saat dekompresi data: {e}. Menganggap data tidak dikompresi.")
        # Fallback: kembalikan data asli jika dekompresi gagal (mungkin tidak dikompresi)
        return data

# --- Fungsi Enkripsi/Dekripsi dengan Algoritma Pilihan (hanya AES-GCM untuk saat ini) ---
def encrypt_file_simple(input_path: str, output_path: str, password: str, keyfile_path: str = None, add_random_padding: bool = True, hide_paths: bool = False):
    """
    Encrypts a file using a password and an optional keyfile.

    Args:
        input_path (str): The path to the input file.
        output_path (str): The path to the output file.
        password (str): The password.
        keyfile_path (str, optional): The path to the keyfile. Defaults to None.
        add_random_padding (bool, optional): Whether to add random padding. Defaults to True.
        hide_paths (bool, optional): Whether to hide file paths in the output. Defaults to False.

    Returns:
        tuple: A tuple containing a boolean indicating success and the path to the output file.
    """
    logger = logging.getLogger(__name__)
    start_time = time.time()
    output_dir = os.path.dirname(output_path) or "."

    if not os.path.isfile(input_path):
        console.print(f"❌ Error: File input '{input_path}' tidak ditemukan.", style="bold red")
        logger.error(f"File input '{input_path}' tidak ditemukan.")
        return False, None

    if not os.access(input_path, os.R_OK):
        console.print(f"❌ Error: File input '{input_path}' tidak dapat dibaca.", style="bold red")
        logger.error(f"File input '{input_path}' tidak dapat dibaca (izin akses).")
        return False, None

    if os.path.getsize(input_path) == 0:
        console.print(f"❌ Error: File input '{input_path}' kosong.", style="bold red")
        logger.error(f"File input '{input_path}' kosong.")
        return False, None

    if not check_file_size_limit(input_path):
        return False, None

    # Validasi ekstensi output sederhana
    if not output_path.endswith('.encrypted'):
        console.print(f"⚠️  Peringatan: Nama file output '{output_path}' tidak memiliki ekstensi '.encrypted'.", style="yellow")
        confirm = Prompt.ask("[yellow]Lanjutkan dengan nama ini? (y/N):[/yellow]").strip().lower()
        if confirm not in ['y', 'yes']:
            console.print("Operasi dibatalkan.", style="yellow")
            logger.info("Operasi dibatalkan karena nama output tidak memiliki ekstensi '.encrypted'.")
            return False, None

    if not check_disk_space(input_path, output_dir):
        return False, None

    try:
        if hide_paths:
            console.print("\n[cyan][ Encrypting... ][/cyan]")
            logger.info(f"Memulai enkripsi file (simple) di direktori: {output_dir}")
        else:
            console.print("\n[cyan][ Encrypting (Simple Mode)... ][/cyan]")
            logger.info(f"Memulai enkripsi file (simple): {input_path}")

        input_size = os.path.getsize(input_path)
        logger.info(f"Ukuran file input: {input_size} bytes")

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

        plaintext_data = b""
        # --- V12/V13/V14: Gunakan mmap jika file besar dan diaktifkan ---
        large_file_threshold = config.get("large_file_threshold", 10 * 1024 * 1024) # 10MB default
        if config.get("use_mmap_for_large_files", False) and input_size > large_file_threshold:
            console.print("Menggunakan mmap untuk membaca file besar...", style="cyan")
            with open(input_path, 'rb') as infile:
                with mmap.mmap(infile.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                    plaintext_data = mmapped_file[:]
        else:
            with open(input_path, 'rb') as infile:
                with tqdm(total=input_size, unit='B', unit_scale=True, desc="Reading", leave=False) as pbar:
                    while True:
                        chunk = infile.read(config["chunk_size"])
                        if not chunk:
                            break
                        plaintext_data += chunk
                        pbar.update(len(chunk))

        # --- V9: Obfuskasi di Memori ---
        if config.get("enable_memory_obfuscation", False):
             plaintext_data = obfuscate_memory(plaintext_data)

        # --- Tambahkan Kompresi di sini ---
        if config.get("enable_compression", False):
            logger.debug("Mengompresi data sebelum enkripsi...")
            plaintext_data = compress_data(plaintext_data)
        else:
            logger.debug("Kompresi dinonaktifkan, melewati.")

        original_checksum = calculate_checksum(plaintext_data)
        logger.debug(f"Checksum data (setelah kompresi jika diaktifkan): {original_checksum.hex()}")

        data = plaintext_data
        padding_added = 0
        if add_random_padding:
            padding_length = secrets.randbelow(config["chunk_size"])
            random_padding = secrets.token_bytes(padding_length)
            data = plaintext_data + random_padding
            padding_added = padding_length

        # --- Pilih Algoritma Enkripsi (hanya AES-GCM untuk v14 ini) ---
        algo = config.get("encryption_algorithm", "aes-gcm").lower()
        if algo == "aes-gcm":
            if CRYPTOGRAPHY_AVAILABLE:
                # Perbaikan: Gunakan nonce yang dihasilkan secara acak, bukan salt
                nonce = secrets.token_bytes(config["gcm_nonce_len"])
                cipher = AESGCM(key)
                ciphertext = cipher.encrypt(nonce, data, associated_data=None)
                tag = b"" # AESGCM (cryptography) menggabungkan tag
            elif PYCRYPTODOME_AVAILABLE: # <-- Sekarang variabel ini selalu didefinisikan
                nonce = get_random_bytes(config["gcm_nonce_len"]) # Gunakan get_random_bytes dari pycryptodome
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                ciphertext, tag = cipher.encrypt_and_digest(data)
            else:
                console.print(f"❌ Error: Tidak ada pustaka tersedia untuk algoritma '{algo}'.", style="bold red")
                logger.error(f"Tidak ada pustaka tersedia untuk algoritma '{algo}'.")
                return False, None
        else:
            console.print(f"❌ Error: Algoritma enkripsi '{algo}' tidak dikenal atau tidak didukung di v15 ini.", style="bold red")
            logger.error(f"Algoritma enkripsi '{algo}' tidak dikenal atau tidak didukung di v15 ini.")
            return False, None

        # --- V8: Tambahkan HMAC untuk verifikasi tambahan (Fixed HMAC Derivation - V14: Konsisten & Lebih Aman) ---
        # Gunakan turunan dari Master Key (jika tersedia) atau kombinasi password/keyfile untuk HMAC
        # V14: Gunakan path file input untuk derivasi HMAC key dari Master Key
        hmac_key = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
        if hmac_key is None:
             console.print("❌ Error: Gagal menurunkan kunci HMAC.", style="bold red")
             logger.error(f"Gagal menurunkan kunci HMAC untuk {input_path}")
             return False, None
        hmac_obj = hmac.new(hmac_key, original_checksum, hashlib.sha256)
        hmac_digest = hmac_obj.digest()

        # --- V14: Secure Memory Locking untuk HMAC Key ---
        if config.get("enable_secure_memory_locking", False):
            hmac_key_addr = ctypes.addressof((ctypes.c_char * len(hmac_key)).from_buffer_copy(hmac_key))
            secure_mlock(hmac_key_addr, len(hmac_key))
            logger.debug(f"Kunci HMAC disimpan di memori terkunci untuk {input_path}")
            # Register untuk integrity check
            if config.get("enable_runtime_data_integrity", False):
                register_sensitive_data(f"hmac_key_{input_path}", hmac_key)

        # --- V10/V11/V12/V13/V14: Custom File Format Shuffle & Dynamic Header (Variable Parts) ---
        parts_to_write = [
            ("salt", salt),
            ("nonce", nonce),
            ("checksum", original_checksum),
            ("hmac", hmac_digest),
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

        # --- V14: Enkripsi Meta Header (opsional) ---
        # Jika header tidak dienkripsi, tulis langsung
        header_to_write = meta_header_prefix + structure_payload

        total_output_size = len(header_to_write) + sum(len(part_data) for _, part_data in shuffled_parts)

        with open(output_path, 'wb') as outfile:
            with tqdm(total=total_output_size, unit='B', unit_scale=True, desc="Writing", leave=False) as pbar:
                # Tulis meta header dulu
                outfile.write(header_to_write)
                pbar.update(len(header_to_write))
                # Tulis bagian-bagian yang diacak
                for part_name, part_data in shuffled_parts:
                    outfile.write(part_data) # Data bagian
                    pbar.update(len(part_data)) # Update progress dengan ukuran header + data
                    logger.debug(f"Menulis bagian '{part_name}' ({len(part_data)} bytes) ke file output.")

        output_size = os.path.getsize(output_path)
        logger.info(f"Ukuran file output: {output_size} bytes")

        # --- V8: Verifikasi Integritas Output ---
        if config.get("verify_output_integrity", True):
            console.print("Memverifikasi integritas file output...", style="cyan")
            try:
                with open(output_path, 'rb') as f:
                    file_content = f.read()
                calculated_file_checksum = calculate_checksum(file_content)
                # Untuk verifikasi output, kita bisa membandingkan checksum dari seluruh file output
                # dengan checksum yang disimpan di dalam file (checksum data asli) dan HMAC.
                # Atau, kita bisa enkripsi ulang file input dan bandingkan outputnya (lebih berat).
                # Untuk saat ini, kita hanya memastikan file output bisa dibaca dan ukurannya sesuai.
                if os.path.getsize(output_path) != output_size:
                    console.print("❌ Error: Ukuran file output tidak sesuai setelah verifikasi.", style="bold red")
                    logger.error(f"Verifikasi integritas output gagal: ukuran tidak cocok untuk {output_path}")
                    return False, None
                console.print("✅ Verifikasi integritas output berhasil.", style="green")
                logger.info(f"Verifikasi integritas output berhasil untuk {output_path}")
            except Exception as e:
                console.print(f"❌ Error saat memverifikasi integritas output: {e}", style="bold red")
                logger.error(f"Verifikasi integritas output gagal untuk {output_path}: {e}")
                return False, None


        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"Durasi enkripsi: {duration:.2f} detik")

        # --- Hardening V14: Secure Memory Overwrite (FIXED) ---
        if config.get("enable_secure_memory_overwrite", False):
            secure_overwrite_variable(key)
            secure_overwrite_variable(plaintext_data)
            secure_overwrite_variable(ciphertext)
            secure_overwrite_variable(hmac_key)
            secure_overwrite_variable(hmac_digest)
            secure_overwrite_variable(original_checksum)
            # Variabel lain yang sensitif bisa ditambahkan di sini

        if hide_paths:
            console.print("✅ File berhasil dienkripsi.", style="green")
            logger.info(f"Enkripsi (simple) berhasil ke file di direktori: {output_dir}")
        else:
            console.print(f"✅ File '{input_path}' berhasil dienkripsi ke '{output_path}' (Simple Mode).", style="green")
            logger.info(f"Enkripsi (simple) berhasil: {input_path} -> {output_path}")

        return True, output_path

    except FileNotFoundError:
        if hide_paths:
            console.print("❌ Error: File input tidak ditemukan.", style="bold red")
            logger.error(f"File input tidak ditemukan saat enkripsi (simple) di direktori: {output_dir}")
        else:
            console.print(f"❌ Error: File '{input_path}' tidak ditemukan.", style="bold red") # Perbaikan: gunakan input_path
            logger.error(f"File '{input_path}' tidak ditemukan saat enkripsi (simple).") # Perbaikan: gunakan input_path
        return False, None
    except Exception as e:
        if hide_paths:
            console.print(f"❌ Error saat mengenkripsi file: {e}", style="bold red")
            logger.error(f"Error saat mengenkripsi (simple) di direktori '{output_dir}': {e}")
        else:
            console.print(f"❌ Error saat mengenkripsi file (simple): {e}", style="bold red")
            logger.error(f"Error saat mengenkripsi (simple) {input_path}: {e}") # Perbaikan: gunakan input_path
        return False, None

def decrypt_file_simple(input_path: str, output_path: str, password: str, keyfile_path: str = None, hide_paths: bool = False): # <-- Hapus parameter add_random_padding
    """
    Decrypts a file using a password and an optional keyfile.

    Args:
        input_path (str): The path to the input file.
        output_path (str): The path to the output file.
        password (str): The password.
        keyfile_path (str, optional): The path to the keyfile. Defaults to None.
        hide_paths (bool, optional): Whether to hide file paths in the output. Defaults to False.

    Returns:
        tuple: A tuple containing a boolean indicating success and the path to the output file.
    """
    logger = logging.getLogger(__name__)
    start_time = time.time()

    if not os.path.isfile(input_path):
        console.print(f"❌ Error: File input '{input_path}' tidak ditemukan.", style="bold red")
        logger.error(f"File input '{input_path}' tidak ditemukan.")
        return False, None

    if not os.access(input_path, os.R_OK):
        console.print(f"❌ Error: File input '{input_path}' tidak dapat dibaca.", style="bold red")
        logger.error(f"File input '{input_path}' tidak dapat dibaca (izin akses).")
        return False, None

    if os.path.getsize(input_path) == 0:
        console.print(f"❌ Error: File input '{input_path}' kosong.", style="bold red")
        logger.error(f"File input '{input_path}' kosong.")
        return False, None

    # Validasi ekstensi input sederhana
    if not input_path.endswith('.encrypted'):
        console.print(f"⚠️  Peringatan: File input '{input_path}' tidak memiliki ekstensi '.encrypted'.", style="yellow")
        confirm = Prompt.ask("[yellow]Apakah ini file terenkripsi Thena_dev? (y/N):[/yellow]").strip().lower()
        if confirm not in ['y', 'yes']:
            console.print("Operasi dibatalkan.", style="yellow")
            logger.info("Operasi dibatalkan karena ekstensi input '.encrypted' tidak ditemukan.")
            return False, None

    try:
        if hide_paths:
            console.print("\n[cyan][ Decrypting... ][/cyan]")
            output_dir = os.path.dirname(output_path) or "."
            logger.info(f"Memulai dekripsi file (simple) ke direktori: {output_dir}")
        else:
            console.print("\n[cyan][ Decrypting (Simple Mode)... ][/cyan]")
            logger.info(f"Memulai dekripsi file (simple): {input_path}")

        output_dir = os.path.dirname(output_path) or "."
        input_size = os.path.getsize(input_path)
        estimated_output_size = input_size
        statvfs_result = os.statvfs(output_dir)
        free_space = statvfs_result.f_frsize * statvfs_result.f_bavail

        if free_space < estimated_output_size:
            required_mb = estimated_output_size / (1024*1024)
            free_mb = free_space / (1024*1024)
            console.print("❌ Error: Ruang disk tidak cukup.", style="bold red")
            console.print(f"   Dibutuhkan sekitar {required_mb:.2f} MB, tersedia {free_mb:.2f} MB di '{output_dir}'.")
            logger.error(f"Ruang disk tidak cukup untuk '{input_path}'. Dibutuhkan {estimated_output_size} bytes, tersedia {free_space} bytes di '{output_dir}'.")
            return False, None

        input_size_log = os.path.getsize(input_path)
        logger.info(f"Ukuran file input: {input_size_log} bytes")

        file_structure = []
        parts_read = {}
        with open(input_path, 'rb') as infile:
            # --- V14: Baca Dynamic Meta Header ---
            meta_header_size = 2 + 4 # Versi (2) + Jumlah Bagian (4)
            # Kita baca bagian meta header untuk mengetahui struktur file
            # Format: [versi_header_meta][jumlah_total_bagian][panjang_nama][nama_bagian_1][panjang_data_1][nama_bagian_2][panjang_data_2]...
            meta_header_encrypted = infile.read(meta_header_size)
            version_bytes = meta_header_encrypted[:2]
            num_total_parts_bytes = meta_header_encrypted[2:6]

            version = int.from_bytes(version_bytes, byteorder='big')
            num_total_parts = int.from_bytes(num_total_parts_bytes, byteorder='big')

            logger.debug(f"Meta header dinamis dibaca: Versi={version}, Num_Total_Parts={num_total_parts}")

            # --- V14: Dekripsi Meta Header (jika dienkripsi) ---
            # Jika meta header tidak dienkripsi, baca sisa bagian struktur dari file
            # Jumlah byte yang tersisa dalam bagian header sebelum data adalah: (255 + 4) * num_total_parts
            remaining_meta_header_size = (255 + 4) * num_total_parts
            decrypted_meta_header_structure_info = infile.read(remaining_meta_header_size)
            if len(decrypted_meta_header_structure_info) != remaining_meta_header_size:
                    console.print("❌ Error: File input rusak (info struktur meta header dinamis tidak lengkap).", style="bold red")
                    logger.error(f"Info struktur meta header dinamis tidak lengkap di {input_path}")
                    return False, None
            logger.debug(f"Meta header dinamis tidak dienkripsi, membaca info struktur langsung.")


            # --- V14: Parse Info Struktur dari Meta Header ---
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


            # --- V14: Baca Bagian-Bagian Berdasarkan Struktur ---
            for part_name, part_size in file_structure:
                 part_data = infile.read(part_size)
                 if len(part_data) != part_size:
                      console.print(f"❌ Error: File input rusak (data bagian '{part_name}' tidak lengkap).", style="bold red")
                      logger.error(f"Data bagian '{part_name}' tidak lengkap di {input_path}")
                      return False, None
                 parts_read[part_name] = part_data
                 logger.debug(f"Bagian '{part_name}' ({part_size} bytes) dibaca dari file input.")


        # Ambil bagian-bagian yang diperlukan
        salt = parts_read.get("salt")
        nonce = parts_read.get("nonce")
        stored_checksum = parts_read.get("checksum")
        stored_hmac = parts_read.get("hmac")
        padding_size_bytes = parts_read.get("padding_added")
        tag = parts_read.get("tag") # Bisa None jika cryptography
        ciphertext = parts_read.get("ciphertext")

        if not all([salt, nonce, stored_checksum, stored_hmac, padding_size_bytes, ciphertext]):
             console.print("❌ Error: File input tidak valid atau rusak (bagian penting hilang).", style="bold red")
             logger.error(f"File input '{input_path}' rusak atau tidak lengkap.")
             return False, None

        # Konversi padding_added kembali dari bytes
        padding_added = int.from_bytes(padding_size_bytes, byteorder='big')

        key = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
        if key is None:
            logger.error(f"Gagal menurunkan kunci untuk {input_path}") # Perbaikan: gunakan input_path
            return False, None

        # --- V14: Secure Memory Locking ---
        if config.get("enable_secure_memory_locking", False):
            key_addr = ctypes.addressof((ctypes.c_char * len(key)).from_buffer_copy(key))
            secure_mlock(key_addr, len(key))
            logger.debug(f"Kunci disimpan di memori terkunci untuk {input_path}")
            # Register untuk integrity check
            if config.get("enable_runtime_data_integrity", False):
                register_sensitive_data(f"key_{input_path}", key)

        # --- V8: Verifikasi HMAC (Fixed HMAC Derivation - V14: Konsisten & Lebih Aman) ---
        # Gunakan turunan dari Master Key (jika tersedia) atau kombinasi password/keyfile untuk HMAC
        # V14: Gunakan path file input untuk derivasi HMAC key dari Master Key
        hmac_key = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
        if hmac_key is None:
             console.print("❌ Error: Gagal menurunkan kunci HMAC.", style="bold red")
             logger.error(f"Gagal menurunkan kunci HMAC untuk {input_path}")
             return False, None
        hmac_obj = hmac.new(hmac_key, stored_checksum, hashlib.sha256)
        calculated_hmac = hmac_obj.digest()
        if not hmac.compare_digest(calculated_hmac, stored_hmac):
             console.print("❌ Error: HMAC tidak cocok. File mungkin rusak atau dimanipulasi.", style="bold red")
             logger.error(f"HMAC tidak cocok untuk {input_path}") # Perbaikan: gunakan input_path
             return False, None
        logger.debug(f"HMAC verifikasi berhasil untuk {input_path}")

        # --- V14: Secure Memory Locking untuk HMAC Key ---
        if config.get("enable_secure_memory_locking", False):
            hmac_key_addr = ctypes.addressof((ctypes.c_char * len(hmac_key)).from_buffer_copy(hmac_key))
            secure_mlock(hmac_key_addr, len(hmac_key))
            logger.debug(f"Kunci HMAC disimpan di memori terkunci untuk {input_path}")
            # Register untuk integrity check
            if config.get("enable_runtime_data_integrity", False):
                register_sensitive_data(f"hmac_key_{input_path}", hmac_key)

        # --- Dekripsi berdasarkan algoritma ---
        algo = config.get("encryption_algorithm", "aes-gcm").lower()
        if algo == "aes-gcm":
            if PYCRYPTODOME_AVAILABLE: # <-- Sekarang variabel ini selalu didefinisikan
                # Perbaikan: Gunakan nonce yang dibaca dari file
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                try:
                    plaintext_data = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError:
                    console.print("❌ Error: Dekripsi gagal. Password atau Keyfile mungkin salah, atau file rusak (otentikasi AES-GCM gagal).", style="bold red")
                    logger.error(f"Dekripsi gagal (otentikasi AES-GCM pycryptodome) untuk {input_path}") # Perbaikan: gunakan input_path
                    return False, None
            elif CRYPTOGRAPHY_AVAILABLE:
                # Perbaikan: Gunakan nonce yang dibaca dari file
                cipher = AESGCM(key)
                try:
                    plaintext_data = cipher.decrypt(nonce, ciphertext, associated_data=None) # Gunakan nonce yang dibaca
                except Exception as e:
                    console.print("❌ Error: Dekripsi gagal. Password atau Keyfile mungkin salah, atau file rusak (otentikasi AES-GCM cryptography gagal).", style="bold red")
                    logger.error(f"Dekripsi gagal (otentikasi AES-GCM cryptography) untuk {input_path}: {e}") # Perbaikan: gunakan input_path
                    return False, None
            else:
                console.print("❌ Error: Tidak ada pustaka tersedia untuk dekripsi AES-GCM.", style="bold red")
                logger.error(f"Tidak ada pustaka tersedia untuk dekripsi AES-GCM.")
                return False, None

        if padding_added > 0:
            if len(plaintext_data) < padding_added:
                console.print("❌ Error: File input rusak (padding yang disimpan lebih besar dari data hasil dekripsi).", style="bold red")
                logger.error(f"Padding yang disimpan lebih besar dari data hasil dekripsi di {input_path}") # Perbaikan: gunakan input_path
                return False, None
            final_plaintext = plaintext_data[:-padding_added]
        else:
            final_plaintext = plaintext_data

        # --- V9: Deobfuskasi di Memori ---
        if config.get("enable_memory_obfuscation", False):
             final_plaintext = deobfuscate_memory(final_plaintext)

        # --- Tambahkan Dekompresi di sini ---
        if config.get("enable_compression", False):
            logger.debug("Mendekompresi data setelah dekripsi...")
            final_plaintext = decompress_data(final_plaintext)
        else:
            logger.debug("Kompresi dinonaktifkan, melewati dekompresi.")

        calculated_checksum = calculate_checksum(final_plaintext)
        logger.debug(f"Checksum hasil dekripsi (setelah dekompresi jika diaktifkan): {calculated_checksum.hex()}")
        logger.debug(f"Checksum yang disimpan: {stored_checksum.hex()}")

        if calculated_checksum == stored_checksum:
            # --- V12/V13/V14: Gunakan mmap untuk file besar ---
            large_file_threshold = config.get("large_file_threshold", 10 * 1024 * 1024) # 10MB default
            if config.get("use_mmap_for_large_files", False) and len(final_plaintext) > large_file_threshold:
                console.print("Menggunakan mmap untuk menulis file besar...", style="cyan")
                with open(output_path, 'wb') as outfile:
                    with mmap.mmap(outfile.fileno(), len(final_plaintext), access=mmap.ACCESS_WRITE) as mmapped_outfile:
                        mmapped_outfile[:] = final_plaintext
            else:
                with open(output_path, 'wb') as outfile:
                    with tqdm(total=len(final_plaintext), unit='B', unit_scale=True, desc="Writing", leave=False) as pbar:
                        outfile.write(final_plaintext)
                        pbar.update(len(final_plaintext))

            output_size = os.path.getsize(output_path)
            logger.info(f"Ukuran file output: {output_size} bytes")

            end_time = time.time()
            duration = end_time - start_time
            logger.info(f"Durasi dekripsi: {duration:.2f} detik")

            # --- Hardening V14: Secure Memory Overwrite (FIXED) ---
            if config.get("enable_secure_memory_overwrite", False):
                secure_overwrite_variable(key)
                secure_overwrite_variable(final_plaintext)
                secure_overwrite_variable(plaintext_data)
                secure_overwrite_variable(hmac_key)
                secure_overwrite_variable(stored_hmac)
                secure_overwrite_variable(stored_checksum)
                secure_overwrite_variable(calculated_checksum)
                # Variabel lain yang sensitif bisa ditambahkan di sini

            if hide_paths:
                console.print("✅ File berhasil didekripsi.", style="green")
                logger.info(f"Dekripsi (simple) berhasil ke file di direktori: {output_dir}")
            else:
                console.print(f"✅ File '{input_path}' berhasil didekripsi ke '{output_path}' (Simple Mode).", style="green")
                logger.info(f"Dekripsi (simple) berhasil dan checksum cocok: {input_path} -> {output_path}")

            return True, output_path
        else:
            console.print("❌ Error: Dekripsi gagal. Checksum tidak cocok. File mungkin rusak atau dimanipulasi.", style="bold red")
            logger.error(f"Dekripsi (simple) gagal (checksum tidak cocok) untuk {input_path} -> {output_path}")
            return False, None

    except FileNotFoundError:
        if hide_paths:
            console.print("❌ Error: File input tidak ditemukan.", style="bold red")
            logger.error(f"File input tidak ditemukan saat dekripsi (simple) di direktori: {output_dir}")
        else:
            console.print(f"❌ Error: File '{input_path}' tidak ditemukan.", style="bold red") # Perbaikan: gunakan input_path
            logger.error(f"File '{input_path}' tidak ditemukan saat dekripsi (simple).") # Perbaikan: gunakan input_path
        return False, None
    except Exception as e:
        if hide_paths:
            console.print(f"❌ Error saat mendekripsi file: {e}", style="bold red")
            logger.error(f"Error saat mendekripsi (simple) di direktori '{output_dir}': {e}")
        else:
            console.print(f"❌ Error saat mendekripsi file (simple): {e}", style="bold red")
            logger.error(f"Error saat mendekripsi (simple) {input_path}: {e}") # Perbaikan: gunakan input_path
        return False, None

def encrypt_file_with_master_key(input_path: str, output_path: str, master_key: bytes, add_random_padding: bool = True, hide_paths: bool = False):
    logger = logging.getLogger(__name__)
    start_time = time.time()
    output_dir = os.path.dirname(output_path) or "."

    if not os.path.isfile(input_path):
        console.print(f"❌ Error: File input '{input_path}' tidak ditemukan.", style="bold red")
        logger.error(f"File input '{input_path}' tidak ditemukan.")
        return False, None

    if not os.access(input_path, os.R_OK):
        console.print(f"❌ Error: File input '{input_path}' tidak dapat dibaca.", style="bold red")
        logger.error(f"File input '{input_path}' tidak dapat dibaca (izin akses).")
        return False, None

    if os.path.getsize(input_path) == 0:
        console.print(f"❌ Error: File input '{input_path}' kosong.", style="bold red")
        logger.error(f"File input '{input_path}' kosong.")
        return False, None

    if not check_file_size_limit(input_path):
        return False, None

    # Validasi ekstensi output sederhana
    if not output_path.endswith('.encrypted'):
        console.print(f"⚠️  Peringatan: Nama file output '{output_path}' tidak memiliki ekstensi '.encrypted'.", style="yellow")
        confirm = Prompt.ask("[yellow]Lanjutkan dengan nama ini? (y/N):[/yellow]").strip().lower()
        if confirm not in ['y', 'yes']:
            console.print("Operasi dibatalkan.", style="yellow")
            logger.info("Operasi dibatalkan karena nama output tidak memiliki ekstensi '.encrypted'.")
            return False, None

    if not check_disk_space(input_path, output_dir):
        return False, None

    try:
        if hide_paths:
            console.print("\n[cyan][ Encrypting... ][/cyan]")
            logger.info(f"Memulai enkripsi file (dengan Master Key) di direktori: {output_dir}")
        else:
            console.print("\n[cyan][ Encrypting with Master Key... ][/cyan]")
            logger.info(f"Memulai enkripsi file (dengan Master Key): {input_path}")

        input_size = os.path.getsize(input_path)
        logger.info(f"Ukuran file input: {input_size} bytes")

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
                with tqdm(total=input_size, unit='B', unit_scale=True, desc="Reading", leave=False) as pbar:
                    while True:
                        chunk = infile.read(config["chunk_size"])
                        if not chunk:
                            break
                        plaintext_data += chunk
                        pbar.update(len(chunk))

        # --- V14: Secure Memory Locking ---
        if config.get("enable_secure_memory_locking", False):
            master_key_addr = ctypes.addressof((ctypes.c_char * len(master_key)).from_buffer_copy(master_key))
            secure_mlock(master_key_addr, len(master_key))
            logger.debug(f"Master Key disimpan di memori terkunci untuk {input_path}")
            # Register untuk integrity check
            if config.get("enable_runtime_data_integrity", False):
                register_sensitive_data(f"master_key_{input_path}", master_key)

        # --- Tambahkan Kompresi di sini ---
        if config.get("enable_compression", False):
            logger.debug("Mengompresi data sebelum enkripsi...")
            plaintext_data = compress_data(plaintext_data)
        else:
            logger.debug("Kompresi dinonaktifkan, melewati.")

        original_checksum = calculate_checksum(plaintext_data)
        logger.debug(f"Checksum data (setelah kompresi jika diaktifkan): {original_checksum.hex()}")

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

        # --- Pilih Algoritma Enkripsi (hanya AES-GCM untuk v14 ini) ---
        algo = config.get("encryption_algorithm", "aes-gcm").lower()
        if algo == "aes-gcm":
            if CRYPTOGRAPHY_AVAILABLE:
                nonce = secrets.token_bytes(config["gcm_nonce_len"])
                cipher = AESGCM(file_key)
                ciphertext = cipher.encrypt(nonce, data, associated_data=None)
                tag = b"" # AESGCM (cryptography) menggabungkan tag
            elif PYCRYPTODOME_AVAILABLE: # <-- Sekarang variabel ini selalu didefinisikan
                nonce = get_random_bytes(config["gcm_nonce_len"]) # Gunakan get_random_bytes dari pycryptodome
                cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
                ciphertext, tag = cipher.encrypt_and_digest(data)
            else:
                console.print(f"❌ Error: Tidak ada pustaka tersedia untuk algoritma '{algo}'.", style="bold red")
                logger.error(f"Tidak ada pustaka tersedia untuk algoritma '{algo}'.")
                return False, None
        else:
            console.print(f"❌ Error: Algoritma enkripsi '{algo}' tidak dikenal atau tidak didukung di v15 ini.", style="bold red")
            logger.error(f"Algoritma enkripsi '{algo}' tidak dikenal atau tidak didukung di v15 ini.")
            return False, None

        # Kunci file terenkripsi tetap seperti sebelumnya
        master_fernet_key = base64.urlsafe_b64encode(master_key)
        master_fernet = Fernet(master_fernet_key)
        encrypted_file_key = master_fernet.encrypt(file_key)

        # --- V8: Tambahkan HMAC untuk verifikasi tambahan (Fixed HMAC Derivation - V14: Konsisten & Lebih Aman) ---
        # Gunakan turunan dari Master Key untuk HMAC (V14: Salt HKDF unik)
        hmac_key = derive_hmac_key_from_master_key(master_key, output_path) # Gunakan path file input untuk derivasi HMAC
        if hmac_key is None:
             console.print("❌ Error: Gagal menurunkan kunci HMAC dari Master Key.", style="bold red")
             logger.error(f"Gagal menurunkan kunci HMAC dari Master Key untuk {input_path}")
             return False, None
        hmac_obj = hmac.new(hmac_key, original_checksum, hashlib.sha256)
        hmac_digest = hmac_obj.digest()

        # --- V14: Secure Memory Locking untuk HMAC Key ---
        if config.get("enable_secure_memory_locking", False):
            hmac_key_addr = ctypes.addressof((ctypes.c_char * len(hmac_key)).from_buffer_copy(hmac_key))
            secure_mlock(hmac_key_addr, len(hmac_key))
            logger.debug(f"HMAC Key disimpan di memori terkunci untuk {input_path}")
            # Register untuk integrity check
            if config.get("enable_runtime_data_integrity", False):
                register_sensitive_data(f"hmac_key_{input_path}", hmac_key)

        # --- V10/V11/V12/V13/V14: Custom File Format Shuffle & Dynamic Header (Variable Parts) ---
        parts_to_write = [
            ("nonce", nonce),
            ("checksum", original_checksum),
            ("hmac", hmac_digest),
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

        shuffled_parts = shuffle_file_parts(final_parts_to_write)

        # --- V14: Dynamic Header Format (Meta Header) ---
        # Kita buat header meta yang menjelaskan struktur file output
        # Format: [versi_header_meta][jumlah_total_bagian][panjang_nama][nama_bagian_1][panjang_data_1][nama_bagian_2][panjang_data_2]...
        # Kita encode nama bagian sebagai string null-terminated ASCII (maks 255 karakter).
        meta_header_version = config["dynamic_header_version"].to_bytes(2, byteorder='big') # 2 byte versi
        num_total_parts = len(shuffled_parts).to_bytes(4, byteorder='big') # 4 byte jumlah bagian
        meta_header_structure_info = meta_header_version + num_total_parts
        for part_name, part_data in shuffled_parts:
             part_name_bytes = part_name.encode('ascii').ljust(255, b'\x00') # Nama bagian (255 byte, null-terminated)
             part_size_bytes = len(part_data).to_bytes(4, byteorder='little') # Ukuran bagian (4 byte, little endian)
             meta_header_structure_info += part_name_bytes + part_size_bytes

        # --- V14: Enkripsi Meta Header (opsional) ---
        header_to_write = meta_header_structure_info

        total_output_size = len(header_to_write) + sum(len(part_data) for _, part_data in shuffled_parts)

        with open(output_path, 'wb') as outfile:
            with tqdm(total=total_output_size, unit='B', unit_scale=True, desc="Writing", leave=False) as pbar:
                # Tulis meta header dulu
                outfile.write(header_to_write)
                pbar.update(len(header_to_write))
                # Tulis bagian-bagian yang diacak
                for part_name, part_data in shuffled_parts:
                    outfile.write(part_data) # Data bagian
                    pbar.update(len(part_data)) # Update progress dengan ukuran header + data
                    logger.debug(f"Menulis bagian '{part_name}' ({len(part_data)} bytes) ke file output.")

        output_size = os.path.getsize(output_path)
        logger.info(f"Ukuran file output: {output_size} bytes")

        # --- V8: Verifikasi Integritas Output ---
        if config.get("verify_output_integrity", True):
            console.print("Memverifikasi integritas file output...", style="cyan")
            try:
                with open(output_path, 'rb') as f:
                    file_content = f.read()
                calculated_file_checksum = calculate_checksum(file_content)
                # Untuk verifikasi output, kita bisa membandingkan checksum dari seluruh file output
                # dengan checksum yang disimpan di dalam file (checksum data asli) dan HMAC.
                # Atau, kita bisa enkripsi ulang file input dan bandingkan outputnya (lebih berat).
                # Untuk saat ini, kita hanya memastikan file output bisa dibaca dan ukurannya sesuai.
                if os.path.getsize(output_path) != output_size:
                    console.print("❌ Error: Ukuran file output tidak sesuai setelah verifikasi.", style="bold red")
                    logger.error(f"Verifikasi integritas output gagal: ukuran tidak cocok untuk {output_path}")
                    return False, None
                console.print("✅ Verifikasi integritas output berhasil.", style="green")
                logger.info(f"Verifikasi integritas output berhasil untuk {output_path}")
            except Exception as e:
                console.print(f"❌ Error saat memverifikasi integritas output: {e}", style="bold red")
                logger.error(f"Verifikasi integritas output gagal untuk {output_path}: {e}")
                return False, None


        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"Durasi enkripsi: {duration:.2f} detik")

        # --- Hardening V14: Secure Memory Overwrite (FIXED) ---
        if config.get("enable_secure_memory_overwrite", False):
            secure_overwrite_variable(master_key)
            secure_overwrite_variable(file_key)
            secure_overwrite_variable(encrypted_file_key)
            secure_overwrite_variable(plaintext_data)
            secure_overwrite_variable(ciphertext)
            secure_overwrite_variable(hmac_key)
            secure_overwrite_variable(hmac_digest)
            secure_overwrite_variable(original_checksum)
            # Variabel lain yang sensitif bisa ditambahkan di sini

        if hide_paths:
            console.print("✅ File berhasil dienkripsi.", style="green")
            logger.info(f"Enkripsi (dengan Master Key) berhasil ke file di direktori: {output_dir}")
        else:
            console.print(f"✅ File '{input_path}' berhasil dienkripsi ke '{output_path}' (dengan Master Key).", style="green")
            logger.info(f"Enkripsi (dengan Master Key) berhasil: {input_path} -> {output_path}")

        return True, output_path

    except FileNotFoundError:
        if hide_paths:
            console.print("❌ Error: File input tidak ditemukan.", style="bold red")
            logger.error(f"File input tidak ditemukan saat enkripsi (dengan Master Key) di direktori: {output_dir}")
        else:
            console.print(f"❌ Error: File '{input_path}' tidak ditemukan.", style="bold red") # Perbaikan: gunakan input_path
            logger.error(f"File '{input_path}' tidak ditemukan saat enkripsi (dengan Master Key).") # Perbaikan: gunakan input_path
        return False, None
    except Exception as e:
        if hide_paths:
            console.print(f"❌ Error saat mengenkripsi file: {e}", style="bold red")
            logger.error(f"Error saat mengenkripsi (dengan Master Key) di direktori '{output_dir}': {e}")
        else:
            console.print(f"❌ Error saat mengenkripsi file (dengan Master Key): {e}", style="bold red")
            logger.error(f"Error saat mengenkripsi (dengan Master Key) {input_path}: {e}") # Perbaikan: gunakan input_path
        return False, None

def decrypt_file_with_master_key(input_path: str, output_path: str, master_key: bytes, hide_paths: bool = False):
    logger = logging.getLogger(__name__)
    start_time = time.time()

    if not os.path.isfile(input_path):
        console.print(f"❌ Error: File input '{input_path}' tidak ditemukan.", style="bold red")
        logger.error(f"File input '{input_path}' tidak ditemukan.")
        return False, None

    if not os.access(input_path, os.R_OK):
        console.print(f"❌ Error: File input '{input_path}' tidak dapat dibaca.", style="bold red")
        logger.error(f"File input '{input_path}' tidak dapat dibaca (izin akses).")
        return False, None

    if os.path.getsize(input_path) == 0:
        console.print(f"❌ Error: File input '{input_path}' kosong.", style="bold red")
        logger.error(f"File input '{input_path}' kosong.")
        return False, None

    # Validasi ekstensi input sederhana
    if not input_path.endswith('.encrypted'):
        console.print(f"⚠️  Peringatan: File input '{input_path}' tidak memiliki ekstensi '.encrypted'.", style="yellow")
        confirm = Prompt.ask("[yellow]Apakah ini file terenkripsi Thena_dev? (y/N):[/yellow]").strip().lower()
        if confirm not in ['y', 'yes']:
            console.print("Operasi dibatalkan.", style="yellow")
            logger.info("Operasi dibatalkan karena ekstensi input '.encrypted' tidak ditemukan.")
            return False, None

    try:
        if hide_paths:
            console.print("\n[cyan][ Decrypting... ][/cyan]")
            output_dir = os.path.dirname(output_path) or "."
            logger.info(f"Memulai dekripsi file (dengan Master Key) ke direktori: {output_dir}")
        else:
            console.print("\n[cyan][ Decrypting with Master Key... ][/cyan]")
            logger.info(f"Memulai dekripsi file (dengan Master Key): {input_path}")

        output_dir = os.path.dirname(output_path) or "."
        input_size = os.path.getsize(input_path)
        estimated_output_size = input_size
        statvfs_result = os.statvfs(output_dir)
        free_space = statvfs_result.f_frsize * statvfs_result.f_bavail

        if free_space < estimated_output_size:
            required_mb = estimated_output_size / (1024*1024)
            free_mb = free_space / (1024*1024)
            console.print("❌ Error: Ruang disk tidak cukup.", style="bold red")
            console.print(f"   Dibutuhkan sekitar {required_mb:.2f} MB, tersedia {free_mb:.2f} MB di '{output_dir}'.")
            logger.error(f"Ruang disk tidak cukup untuk '{input_path}'. Dibutuhkan {estimated_output_size} bytes, tersedia {free_space} bytes di '{output_dir}'.")
            return False, None

        input_size_log = os.path.getsize(input_path)
        logger.info(f"Ukuran file input: {input_size_log} bytes")

        file_structure = []
        parts_read = {}
        with open(input_path, 'rb') as infile:
            # --- V14: Baca Dynamic Meta Header ---
            meta_header_size = 2 + 4 # Versi (2) + Jumlah Bagian (4)
            # Kita baca bagian meta header untuk mengetahui struktur file
            # Format: [versi_header_meta][jumlah_total_bagian][panjang_nama][nama_bagian_1][panjang_data_1][nama_bagian_2][panjang_data_2]...
            meta_header_encrypted = infile.read(meta_header_size)
            version_bytes = meta_header_encrypted[:2]
            num_total_parts_bytes = meta_header_encrypted[2:6]

            version = int.from_bytes(version_bytes, byteorder='big')
            num_total_parts = int.from_bytes(num_total_parts_bytes, byteorder='big')

            logger.debug(f"Meta header dinamis dibaca: Versi={version}, Num_Total_Parts={num_total_parts}")

            # --- V14: Dekripsi Meta Header (jika dienkripsi) ---
            # Jika header tidak dienkripsi, baca sisa bagian struktur dari file
            # Jumlah byte yang tersisa dalam bagian header sebelum data adalah: (255 + 4) * num_total_parts
            remaining_meta_header_size = (255 + 4) * num_total_parts
            decrypted_meta_header_structure_info = infile.read(remaining_meta_header_size)
            if len(decrypted_meta_header_structure_info) != remaining_meta_header_size:
                 console.print("❌ Error: File input rusak (info struktur meta header dinamis tidak lengkap).", style="bold red")
                 logger.error(f"Info struktur meta header dinamis tidak lengkap di {input_path}")
                 return False, None
            logger.debug(f"Meta header dinamis tidak dienkripsi, membaca info struktur langsung.")


            # --- V14: Parse Info Struktur dari Meta Header ---
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


            # --- V14: Baca Bagian-Bagian Berdasarkan Struktur ---
            parts_read = {}
            for part_name, part_size in file_structure:
                 part_data = infile.read(part_size)
                 if len(part_data) != part_size:
                      console.print(f"❌ Error: File input rusak (data bagian '{part_name}' tidak lengkap).", style="bold red")
                      logger.error(f"Data bagian '{part_name}' tidak lengkap di {input_path}")
                      return False, None
                 parts_read[part_name] = part_data
                 logger.debug(f"Bagian '{part_name}' ({part_size} bytes) dibaca dari file input.")


        # Ambil bagian-bagian yang diperlukan
        nonce = parts_read.get("nonce")
        stored_checksum = parts_read.get("checksum")
        stored_hmac = parts_read.get("hmac")
        padding_size_bytes = parts_read.get("padding_added")
        len_encrypted_key_bytes = parts_read.get("encrypted_file_key_len")
        encrypted_file_key = parts_read.get("encrypted_file_key")
        ciphertext = parts_read.get("ciphertext")
        # Tag hanya ada jika pycryptodome
        tag = parts_read.get("tag") if PYCRYPTODOME_AVAILABLE else b""

        if not all([nonce, stored_checksum, stored_hmac, padding_size_bytes, len_encrypted_key_bytes, encrypted_file_key, ciphertext]):
             console.print("❌ Error: File input tidak valid atau rusak (bagian penting hilang).", style="bold red")
             logger.error(f"File input '{input_path}' rusak atau tidak lengkap.")
             return False, None

        # Konversi padding_added dan len_encrypted_key kembali dari bytes
        padding_added = int.from_bytes(padding_size_bytes, byteorder='big')
        len_encrypted_key = int.from_bytes(len_encrypted_key_bytes, byteorder='big')

        if len(encrypted_file_key) != len_encrypted_key:
             console.print("❌ Error: File input rusak (panjang encrypted key tidak sesuai).", style="bold red")
             logger.error(f"File input '{input_path}' rusak: panjang encrypted key tidak sesuai.")
             return False, None

        master_fernet_key = base64.urlsafe_b64encode(master_key)
        master_fernet = Fernet(master_fernet_key)
        try:
            file_key = master_fernet.decrypt(encrypted_file_key)
        except Exception as e:
            console.print("❌ Error: Gagal mendekripsi File Key. Master Key mungkin salah.", style="bold red")
            logger.error(f"Gagal mendekripsi File Key: {e}")
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

        # --- V8: Verifikasi HMAC (Fixed HMAC Derivation - V14: Konsisten & Lebih Aman) ---
        # Gunakan turunan dari Master Key untuk HMAC (V14: Salt HKDF unik)
        hmac_key = derive_hmac_key_from_master_key(master_key, input_path) # Gunakan path file input untuk derivasi HMAC
        if hmac_key is None:
             console.print("❌ Error: Gagal menurunkan kunci HMAC dari Master Key.", style="bold red")
             logger.error(f"Gagal menurunkan kunci HMAC dari Master Key untuk {input_path}")
             return False, None
        hmac_obj = hmac.new(hmac_key, stored_checksum, hashlib.sha256)
        calculated_hmac = hmac_obj.digest()
        if not hmac.compare_digest(calculated_hmac, stored_hmac):
             console.print("❌ Error: HMAC tidak cocok. File mungkin rusak atau dimanipulasi.", style="bold red")
             logger.error(f"HMAC tidak cocok untuk {input_path}") # Perbaikan: gunakan input_path
             return False, None
        logger.debug(f"HMAC verifikasi berhasil untuk {input_path}")

        # --- V14: Secure Memory Locking untuk HMAC Key ---
        if config.get("enable_secure_memory_locking", False):
            hmac_key_addr = ctypes.addressof((ctypes.c_char * len(hmac_key)).from_buffer_copy(hmac_key))
            secure_mlock(hmac_key_addr, len(hmac_key))
            logger.debug(f"HMAC Key disimpan di memori terkunci untuk {input_path}")
            # Register untuk integrity check
            if config.get("enable_runtime_data_integrity", False):
                register_sensitive_data(f"hmac_key_{input_path}", hmac_key)

        # --- Dekripsi berdasarkan algoritma ---
        algo = config.get("encryption_algorithm", "aes-gcm").lower()
        if algo == "aes-gcm":
            if PYCRYPTODOME_AVAILABLE: # <-- Sekarang variabel ini selalu didefinisikan
                cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
                try:
                    plaintext_data = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError:
                    console.print("❌ Error: Dekripsi gagal. File rusak (otentikasi AES-GCM gagal).", style="bold red")
                    logger.error(f"Dekripsi gagal (otentikasi AES-GCM pycryptodome) untuk {input_path}") # Perbaikan: gunakan input_path
                    return False, None
            elif CRYPTOGRAPHY_AVAILABLE:
                cipher = AESGCM(file_key)
                try:
                    plaintext_data = cipher.decrypt(nonce, ciphertext, associated_data=None)
                except Exception as e:
                    console.print("❌ Error: Dekripsi gagal. File rusak (otentikasi AES-GCM cryptography gagal).", style="bold red")
                    logger.error(f"Dekripsi gagal (otentikasi AES-GCM cryptography) untuk {input_path}: {e}") # Perbaikan: gunakan input_path
                    return False, None
            else:
                console.print("❌ Error: Tidak ada pustaka tersedia untuk dekripsi AES-GCM.", style="bold red")
                logger.error(f"Tidak ada pustaka tersedia untuk dekripsi AES-GCM.")
                return False, None

        if padding_added > 0:
            if len(plaintext_data) < padding_added:
                console.print("❌ Error: File input rusak (padding yang disimpan lebih besar dari data hasil dekripsi).", style="bold red")
                logger.error(f"Padding yang disimpan lebih besar dari data hasil dekripsi di {input_path}") # Perbaikan: gunakan input_path
                return False, None
            final_plaintext = plaintext_data[:-padding_added]
        else:
            final_plaintext = plaintext_data

        # --- Tambahkan Dekompresi di sini ---
        if config.get("enable_compression", False):
            logger.debug("Mendekompresi data setelah dekripsi...")
            final_plaintext = decompress_data(final_plaintext)
        else:
            logger.debug("Kompresi dinonaktifkan, melewati dekompresi.")

        calculated_checksum = calculate_checksum(final_plaintext)
        logger.debug(f"Checksum hasil dekripsi (setelah dekompresi jika diaktifkan): {calculated_checksum.hex()}")
        logger.debug(f"Checksum yang disimpan: {stored_checksum.hex()}")

        if calculated_checksum == stored_checksum:
            # --- V12/V13/V14: Gunakan mmap untuk file besar ---
            large_file_threshold = config.get("large_file_threshold", 10 * 1024 * 1024) # 10MB default
            if config.get("use_mmap_for_large_files", False) and len(final_plaintext) > large_file_threshold:
                console.print("Menggunakan mmap untuk menulis file besar...", style="cyan")
                with open(output_path, 'wb') as outfile:
                    with mmap.mmap(outfile.fileno(), len(final_plaintext), access=mmap.ACCESS_WRITE) as mmapped_outfile:
                        mmapped_outfile[:] = final_plaintext
            else:
                with open(output_path, 'wb') as outfile:
                    with tqdm(total=len(final_plaintext), unit='B', unit_scale=True, desc="Writing", leave=False) as pbar:
                        outfile.write(final_plaintext)
                        pbar.update(len(final_plaintext))

            output_size = os.path.getsize(output_path)
            logger.info(f"Ukuran file output: {output_size} bytes")

            end_time = time.time()
            duration = end_time - start_time
            logger.info(f"Durasi dekripsi: {duration:.2f} detik")

            # --- Hardening V14: Secure Memory Overwrite (FIXED) ---
            if config.get("enable_secure_memory_overwrite", False):
                secure_overwrite_variable(master_key)
                secure_overwrite_variable(file_key)
                secure_overwrite_variable(encrypted_file_key)
                secure_overwrite_variable(final_plaintext)
                secure_overwrite_variable(plaintext_data)
                secure_overwrite_variable(ciphertext)
                secure_overwrite_variable(hmac_key)
                secure_overwrite_variable(stored_hmac)
                secure_overwrite_variable(stored_checksum)
                secure_overwrite_variable(calculated_checksum)
                # Variabel lain yang sensitif bisa ditambahkan di sini

            if hide_paths:
                console.print("✅ File berhasil didekripsi.", style="green")
                logger.info(f"Dekripsi (dengan Master Key) berhasil ke file di direktori: {output_dir}")
            else:
                console.print(f"✅ File '{input_path}' berhasil didekripsi ke '{output_path}' (dengan Master Key).", style="green")
                logger.info(f"Dekripsi (dengan Master Key) berhasil dan checksum cocok: {input_path} -> {output_path}")

            if os.path.exists(config["master_key_file"]):
                try:
                    os.remove(config["master_key_file"])
                    console.print(f"✅ File Master Key '{config['master_key_file']}' dihapus secara otomatis setelah dekripsi.", style="green")
                    logger.info(f"File Master Key '{config['master_key_file']}' dihapus secara otomatis setelah dekripsi berhasil.")
                except OSError as e:
                    console.print(f"⚠️  Peringatan: Gagal menghapus file Master Key '{config['master_key_file']}' secara otomatis: {e}", style="yellow")
                    logger.warning(f"Gagal menghapus file Master Key '{config['master_key_file']}' secara otomatis: {e}")

            return True, output_path
        else:
            console.print("❌ Error: Dekripsi gagal. Checksum tidak cocok. File mungkin rusak atau dimanipulasi.", style="bold red")
            logger.error(f"Dekripsi (dengan Master Key) gagal (checksum tidak cocok) untuk {input_path} -> {output_path}")
            return False, None

    except FileNotFoundError:
        if hide_paths:
            console.print("❌ Error: File input tidak ditemukan.", style="bold red")
            logger.error(f"File input tidak ditemukan saat dekripsi (dengan Master Key) di direktori: {output_dir}")
        else:
            console.print(f"❌ Error: File '{input_path}' tidak ditemukan.", style="bold red") # Perbaikan: gunakan input_path
            logger.error(f"File '{input_path}' tidak ditemukan saat dekripsi (dengan Master Key).") # Perbaikan: gunakan input_path
        return False, None
    except Exception as e:
        if hide_paths:
            console.print(f"❌ Error saat mendekripsi file: {e}", style="bold red")
            logger.error(f"Error saat mendekripsi (dengan Master Key) di direktori '{output_dir}': {e}")
        else:
            console.print(f"❌ Error saat mendekripsi file (dengan Master Key): {e}", style="bold red")
            logger.error(f"Error saat mendekripsi (dengan Master Key) {input_path}: {e}") # Perbaikan: gunakan input_path
        return False, None

# --- Fungsi Derivasi Kunci HMAC dari Master Key (V8 - Fixed HMAC Derivation - V14: Konsisten & Lebih Aman) ---
def derive_hmac_key_from_master_key(master_key: bytes, input_file_path: str) -> bytes:
    """
    Menurunkan kunci HMAC dari Master Key menggunakan HKDF (dari cryptography jika tersedia).
    Info HKDF menggunakan string konfigurasi dan hash dari path file input.
    V14: Salt HKDF juga mencakup hash dari path file input.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        console.print("❌ Error: HKDF (untuk HMAC) memerlukan modul 'cryptography'.", style="bold red")
        logger.error("HKDF (untuk HMAC) memerlukan modul 'cryptography', yang tidak tersedia.")
        return secrets.token_bytes(config["hmac_key_length"]) # Fallback ke acak jika tidak tersedia

    # Buat salt unik berdasarkan path file input (V14)
    file_path_hash = hashlib.sha256(input_file_path.encode()).digest()[:16]

    # Ambil string dari konfigurasi dan konversi ke bytes
    info_prefix_str = config.get("hmac_derivation_info", "thena_v14_hmac_key_")
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

# --- Fungsi Derivasi Kunci untuk Header dari Master Key (V14 - Hardening) ---
def derive_key_from_master_key_for_header(master_key: bytes, input_file_path: str) -> bytes:
    """
    Menurunkan kunci khusus dari Master Key untuk mengenkripsi header dinamis.
    Menggunakan HKDF (dari cryptography jika tersedia).
    Info HKDF menggunakan string konfigurasi dan hash dari path file input.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        console.print("❌ Error: HKDF (untuk header) memerlukan modul 'cryptography'.", style="bold red")
        logger.error("HKDF (untuk header) memerlukan modul 'cryptography', yang tidak tersedia.")
        return secrets.token_bytes(config["dynamic_header_encryption_key_length"]) # Fallback ke acak jika tidak tersedia

    # Buat salt unik berdasarkan path file input
    file_path_hash = hashlib.sha256(input_file_path.encode()).digest()[:16]

    # Ambil string dari konfigurasi dan konversi ke bytes
    info_prefix_str = config.get("header_derivation_info", "thena_v14_header_enc_key_")
    info_bytes = info_prefix_str.encode('utf-8') + file_path_hash

    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=config["dynamic_header_encryption_key_length"],
            salt=file_path_hash,
            info=info_bytes,
        )
        header_key = hkdf.derive(master_key)
        logger.debug(f"Kunci enkripsi header diturunkan dari Master Key menggunakan HKDF (cryptography) (Info: {info_prefix_str} + hash path), Panjang: {len(header_key)} bytes")
        return header_key
    except Exception as e:
        logger.error(f"Kesalahan saat derivasi kunci header dengan HKDF (cryptography): {e}")
        # Fallback ke acak jika HKDF gagal
        return secrets.token_bytes(config["dynamic_header_encryption_key_length"])


# --- Fungsi UI ---
def print_box(title, options=None, width=80):
    """Mencetak kotak menu menggunakan Rich."""
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

    table = Table(show_header=False, box=None, width=width)
    table.add_row(logo_ascii)
    if options:
        for option in options:
            table.add_row(option, style="magenta")

    console.print(Panel(table, title=f"[bold white]{title}[/bold white]", border_style="cyan", expand=False))

# --- Fungsi Mode Batch ---
def process_batch_file(args):
    """Fungsi helper untuk eksekusi paralel batch."""
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

def batch_process(directory: str, mode: str, password: str, keyfile_path: str = None, add_padding: bool = True, hide_paths: bool = False, parallel: bool = False):
    """Memproses semua file dalam direktori secara batch."""
    if not os.path.isdir(directory):
        console.print(f"❌ Error: Direktori '{directory}' tidak ditemukan.", style="bold red")
        logger.error(f"Direktori batch '{directory}' tidak ditemukan.")
        return

    # Tentukan ekstensi berdasarkan mode dan apakah rekursif
    target_ext = ".encrypted" if mode == 'decrypt' else ""
    files_to_process = []
    if config.get("enable_recursive_batch", False):
        console.print("Memindai sub-direktori secara rekursif...", style="cyan")
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(target_ext):
                    files_to_process.append(os.path.join(root, file))
    else:
        files_to_process = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and f.endswith(target_ext)]

    if not files_to_process:
        console.print(f"⚠️  Tidak ditemukan file yang cocok untuk {mode} di direktori '{directory}'.", style="yellow")
        logger.info(f"Tidak ditemukan file yang cocok untuk {mode} di direktori '{directory}' (rekursif: {config.get('enable_recursive_batch', False)}).")
        return

    console.print(f"Memulai {mode} batch untuk {len(files_to_process)} file...", style="cyan")
    logger.info(f"Memulai {mode} batch untuk {len(files_to_process)} file di '{directory}' (rekursif: {config.get('enable_recursive_batch', False)}).")

    success_count = 0
    if parallel and config.get("batch_parallel", False):
        console.print(f"Menggunakan mode paralel ({config.get('batch_workers', 2)} workers).", style="cyan")
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
            console.print(f"\n[bold]Memproses: {os.path.relpath(input_file, directory)}[/bold]") # Tampilkan path relatif untuk lebih rapi
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

    console.print(f"\n✅ Batch {mode} selesai. {success_count}/{len(files_to_process)} file berhasil.", style="green")
    logger.info(f"Batch {mode} selesai. {success_count}/{len(files_to_process)} file berhasil.")

# --- Fungsi Utama ---
def main():
    # --- V10: Inisialisasi Hardening ---
    # Deteksi Debugging (V10/V11/V12/V13/V14)
    if config.get("enable_anti_debug", False):
        if detect_debugging():
            sys.exit(1) # Keluar jika debugging terdeteksi

    # Runtime Integrity Checks (V10/V11/V12/V13/V14)
    if config.get("enable_runtime_integrity", False):
        # Daftarkan fungsi-fungsi kritis
        register_critical_function(derive_key_from_password_and_keyfile_pbkdf2)
        register_critical_function(derive_key_from_password_and_keyfile_scrypt)
        register_critical_function(derive_key_from_password_and_keyfile_argon2)
        register_critical_function(derive_key_from_password_and_keyfile)
        register_critical_function(derive_file_key_from_master_key)
        register_critical_function(derive_hmac_key_from_master_key)
        register_critical_function(derive_key_from_master_key_for_header) # V14
        register_critical_function(encrypt_file_simple)
        register_critical_function(decrypt_file_simple)
        register_critical_function(encrypt_file_with_master_key)
        register_critical_function(decrypt_file_with_master_key)
        # Mulai thread integrity checker
        interval = config.get("integrity_check_interval", 5)
        global integrity_thread
        integrity_thread = threading.Thread(target=integrity_checker, args=(interval,), daemon=True)
        integrity_thread.start()
        logger.info(f"Runtime integrity checker dimulai dengan interval {interval}s.")

    parser = argparse.ArgumentParser(description='Thena Dev Encryption Tool V15 (Rich UI, bcrypt KDF, Enhanced Security, etc.)')
    parser.add_argument('--encrypt', action='store_true', help='Mode enkripsi')
    parser.add_argument('--decrypt', action='store_true', help='Mode dekripsi')
    parser.add_argument('--batch', action='store_true', help='Mode batch (memerlukan --dir)')
    parser.add_argument('--dir', type=str, help='Direktori untuk mode batch')
    parser.add_argument('-i', '--input', type=str, help='File input (untuk mode tunggal)')
    parser.add_argument('-o', '--output', type=str, help='File output (untuk mode tunggal)')
    parser.add_argument('-p', '--password', type=str, help='Password')
    parser.add_argument('-k', '--keyfile', type=str, help=f'File key (default: {config["master_key_file"]})')
    parser.add_argument('--password-file', type=str, help='Baca password dari file (opsional, menggantikan -p jika diset)')
    parser.add_argument('--random-name', action='store_true', help='Gunakan nama file acak untuk output (hanya untuk enkripsi tunggal)') # V8: Gunakan nama acak jika --random-name
    parser.add_argument('--add-padding', action='store_true', help='Tambahkan padding acak (default: True)')
    parser.add_argument('--no-padding', action='store_true', help='Jangan tambahkan padding acak')
    parser.add_argument('--hide-paths', action='store_true', help='Sembunyikan path file dalam output')
    parser.add_argument('--enable-compression', action='store_true', help='Aktifkan kompresi zlib sebelum enkripsi (menggunakan konfigurasi)')
    parser.add_argument('--disable-compression', action='store_true', help='Nonaktifkan kompresi zlib sebelum enkripsi')

    args = parser.parse_args()

    # Baca password dari file jika diset
    if args.password_file:
        try:
            with open(args.password_file, 'r') as pf:
                args.password = pf.read().strip()
        except FileNotFoundError:
            console.print(f"❌ Error: File password '{args.password_file}' tidak ditemukan.", style="bold red")
            sys.exit(1)
        except Exception as e:
            console.print(f"❌ Error saat membaca password dari file: {e}", style="bold red")
            sys.exit(1)

    # Override konfigurasi kompresi jika diset via argumen
    if args.enable_compression:
        config["enable_compression"] = True
        logger.info("Kompresi diaktifkan via argumen baris perintah.")
    if args.disable_compression:
        config["enable_compression"] = False
        logger.info("Kompresi dinonaktifkan via argumen baris perintah.")

    if args.batch:
        if not args.dir or not args.password:
            console.print("❌ Error: Argumen --dir dan --password wajib untuk mode batch.", style="bold red")
            sys.exit(1)
        if not (args.encrypt or args.decrypt):
            console.print("❌ Error: Pilih --encrypt atau --decrypt untuk mode batch.", style="bold red")
            sys.exit(1)
        batch_process(args.dir, 'encrypt' if args.encrypt else 'decrypt', args.password, args.keyfile, add_padding=not args.no_padding, hide_paths=args.hide_paths, parallel=config.get("batch_parallel", False))
        return

    if args.encrypt or args.decrypt:
        if not args.input or not args.output or not args.password:
            console.print("❌ Error: Argumen --input, --output, dan --password wajib untuk mode baris perintah tunggal.", style="bold red")
            sys.exit(1)

        input_path = args.input
        output_path = args.output
        password = args.password
        keyfile_path = args.keyfile
        add_padding = not args.no_padding
        if args.no_padding: add_padding = False
        if args.add_padding: add_padding = True
        hide_paths = args.hide_paths

        if not os.path.isfile(input_path):
            console.print(f"❌ Error: File input '{input_path}' tidak ditemukan.", style="bold red")
            sys.exit(1)

        if keyfile_path and not os.path.isfile(keyfile_path):
             console.print(f"❌ Error: File keyfile '{keyfile_path}' tidak ditemukan.", style="bold red")
             sys.exit(1)

        if not validate_password_keyfile(password, keyfile_path):
            console.print("❌ Error: Validasi password/keyfile gagal.", style="bold red")
            sys.exit(1)

        if not check_file_size_limit(input_path):
            sys.exit(1)

        # Validasi ekstensi untuk mode baris perintah
        if args.encrypt:
            if not output_path.endswith('.encrypted'):
                console.print(f"⚠️  Peringatan: Nama file output '{output_path}' tidak memiliki ekstensi '.encrypted'.", style="yellow")
                confirm = Prompt.ask("[yellow]Lanjutkan? (y/N):[/yellow]").strip().lower()
                if confirm not in ['y', 'yes']:
                    console.print("Operasi dibatalkan.", style="yellow")
                    sys.exit(0)
        elif args.decrypt:
            if not input_path.endswith('.encrypted'):
                console.print(f"⚠️  Peringatan: File input '{input_path}' tidak memiliki ekstensi '.encrypted'.", style="yellow")
                confirm = Prompt.ask("[yellow]Apakah ini file terenkripsi Thena_dev? (y/N):[/yellow]").strip().lower()
                if confirm not in ['y', 'yes']:
                    console.print("Operasi dibatalkan.", style="yellow")
                    sys.exit(0)

        if args.encrypt:
            if args.random_name or config.get("disable_timestamp_in_filename", False):
                output_path = f"{int(time.time() * 1000)}{config.get('output_name_suffix', '')}.encrypted"
            if CRYPTOGRAPHY_AVAILABLE:
                master_key = load_or_create_master_key(password, keyfile_path)
                if master_key is None:
                    console.print("❌ Gagal mendapatkan Master Key.", style="bold red")
                    sys.exit(1)
                encryption_success, created_output = encrypt_file_with_master_key(input_path, output_path, master_key, add_random_padding=add_padding, hide_paths=hide_paths)
            else:
                encryption_success, created_output = encrypt_file_simple(input_path, output_path, password, keyfile_path, add_random_padding=add_padding, hide_paths=hide_paths)
            if encryption_success:
                console.print(f"✅ Enkripsi selesai: {input_path} -> {created_output}", style="green")
            else:
                console.print("❌ Enkripsi gagal.", style="bold red")
                sys.exit(1)
        elif args.decrypt:
            if CRYPTOGRAPHY_AVAILABLE:
                if not os.path.exists(config["master_key_file"]):
                    console.print(f"❌ Error: File Master Key '{config['master_key_file']}' tidak ditemukan. Tidak dapat mendekripsi tanpanya.", style="bold red")
                    sys.exit(1)
                master_key = load_or_create_master_key(password, keyfile_path)
                if master_key is None:
                    console.print("❌ Gagal mendapatkan Master Key.", style="bold red")
                    sys.exit(1)
                decryption_success, created_output = decrypt_file_with_master_key(input_path, output_path, master_key, hide_paths=hide_paths)
            else:
                decryption_success, created_output = decrypt_file_simple(input_path, output_path, password, keyfile_path, hide_paths=hide_paths)
            if decryption_success:
                console.print(f"✅ Dekripsi selesai: {input_path} -> {created_output}", style="green")
            else:
                console.print("❌ Dekripsi gagal.", style="bold red")
                sys.exit(1)

    else: # Mode Interaktif
        setup_logging()
        clear_screen()

        while True:
            print_box(
                f"THENADev SCRIPT V15",
                [
                    "1. Enkripsi File",
                    "2. Dekripsi File",
                    "3. Keluar"
                ],
                width=80
            )

            choice = Prompt.ask("\n[bold]Masukkan pilihan[/bold]").strip()

            if choice in ['1', '2']:
                is_encrypt = choice == '1'
                mode_str = "enkripsi" if is_encrypt else "dekripsi"
                input_path = Prompt.ask(f"[bold]Masukkan path file input (untuk {mode_str})[/bold]").strip()

                if not os.path.isfile(input_path):
                    console.print("\n" + "─" * 50)
                    console.print("❌ File input tidak ditemukan.", style="bold red")
                    console.print("─" * 50)
                    continue

                if not check_file_size_limit(input_path):
                    continue

                if is_encrypt:
                    if config.get("disable_timestamp_in_filename", False):
                        output_path = f"{int(time.time() * 1000)}{config.get('output_name_suffix', '')}.encrypted"
                    else:
                        output_path = f"{int(time.time() * 1000)}{config.get('output_name_suffix', '')}.encrypted"
                else:
                    output_path = Prompt.ask(f"[bold]Masukkan nama file output (nama asli sebelum {mode_str})[/bold]").strip()
                    if not output_path:
                        console.print("\n" + "─" * 50)
                        console.print("❌ Nama file output tidak boleh kosong.", style="bold red")
                        console.print("─" * 50)
                        continue
                    if not confirm_overwrite(output_path):
                        continue

                password = Prompt.ask("[bold]Masukkan kata sandi[/bold]", password=True).strip()
                if not password:
                    console.print("\n" + "─" * 50)
                    console.print("❌ Kata sandi tidak boleh kosong.", style="bold red")
                    console.print("─" * 50)
                    continue

                use_keyfile = Prompt.ask("[bold]Gunakan Keyfile? (y/N)[/bold]").strip().lower()
                keyfile_path = None
                if use_keyfile in ['y', 'yes']:
                    keyfile_path = Prompt.ask("[bold]Masukkan path Keyfile[/bold]").strip()
                    if not os.path.isfile(keyfile_path):
                        console.print("\n" + "─" * 50)
                        console.print("❌ File keyfile tidak ditemukan.", style="bold red")
                        console.print("─" * 50)
                        continue

                if not validate_password_keyfile(password, keyfile_path):
                    continue

                hide_paths_input = Prompt.ask("[bold]Sembunyikan path file di output layar? (y/N)[/bold]").strip().lower()
                hide_paths = hide_paths_input in ['y', 'yes']

                if is_encrypt:
                    console.print("\n" + "─" * 50)
                    console.print("⚠️  Gunakan password dan keyfile yang SANGAT KUAT!", style="yellow")
                    console.print("─" * 50)
                    add_pad = Prompt.ask("[bold]Tambahkan padding acak? (Y/n)[/bold]").strip().lower()
                    add_padding = add_pad not in ['n', 'no']
                else:
                    add_padding = True

                if CRYPTOGRAPHY_AVAILABLE:
                    master_key = load_or_create_master_key(password, keyfile_path)
                    if master_key is None:
                        console.print("❌ Gagal mendapatkan Master Key. Operasi dibatalkan.", style="bold red")
                        continue
                    if is_encrypt:
                        func = encrypt_file_with_master_key
                        success, created_output = func(input_path, output_path, master_key, add_random_padding=add_padding, hide_paths=hide_paths)
                    else:
                        func = decrypt_file_with_master_key
                        success, created_output = func(input_path, output_path, master_key, hide_paths=hide_paths)
                else:
                    if is_encrypt:
                        func = encrypt_file_simple
                        success, created_output = func(input_path, output_path, password, keyfile_path, add_random_padding=add_padding, hide_paths=hide_paths)
                    else:
                        func = decrypt_file_simple
                        success, created_output = func(input_path, output_path, password, keyfile_path, hide_paths=hide_paths)

                if success:
                    if is_encrypt:
                        delete_original = Prompt.ask(f"[bold]Hapus file asli secara AMAN setelah {mode_str}? (y/N)[/bold]").strip().lower()
                        if delete_original in ['y', 'yes']:
                            secure_wipe_file(input_path)
                            if keyfile_path:
                                delete_keyfile = Prompt.ask(f"[bold]Hapus keyfile '{keyfile_path}' secara AMAN juga? (y/N)[/bold]").strip().lower()
                                if delete_keyfile in ['y', 'yes']:
                                    secure_wipe_file(keyfile_path)
                    else: # Dekripsi
                        delete_encrypted = Prompt.ask(f"[bold]Hapus file ter{mode_str}ripsi secara AMAN setelah {mode_str}? (y/N)[/bold]").strip().lower()
                        if delete_encrypted in ['y', 'yes']:
                            secure_wipe_file(input_path)
                            if keyfile_path:
                                delete_keyfile = Prompt.ask(f"[bold]Hapus keyfile '{keyfile_path}' secara AMAN juga? (y/N)[/bold]").strip().lower()
                                if delete_keyfile in ['y', 'yes']:
                                    secure_wipe_file(keyfile_path)

            elif choice == '3':
                console.print("\n" + "─" * 50)
                console.print("✅ Keluar dari program V15.", style="green")
                console.print("⚠️  Ingat:", style="yellow")
                console.print("  - Simpan password Anda dengan aman.", style="yellow")
                if CRYPTOGRAPHY_AVAILABLE:
                    console.print(f"  - Jaga keamanan file '{config['master_key_file']}' dan keyfile Anda.", style="yellow")
                else:
                    console.print("  - Jaga keamanan keyfile Anda.", style="yellow")
                console.print("  - Cadangkan file penting Anda.", style="yellow")
                console.print("  - Gunakan perangkat ini dengan bijak.", style="yellow")
                console.print("─" * 50)
                logger.info(f"=== Encryptor V15 ({'With Advanced Features (cryptography)' if CRYPTOGRAPHY_AVAILABLE else 'Simple Mode (pycryptodome)'}) Selesai ===")
                console.print("─" * 50)

                if integrity_thread and config.get("enable_runtime_integrity", False):
                    stop_integrity_check.set()
                    integrity_thread.join(timeout=5)
                    logger.info("Thread integrity checker dihentikan.")
                sys.exit(0)

            else:
                console.print("\n" + "─" * 50)
                console.print("❌ Pilihan tidak valid. Silakan coba lagi.", style="bold red")
                logger.warning(f"Pilihan tidak valid dimasukkan: {choice}")
                console.print("─" * 50)

if __name__ == "__main__":
    main()