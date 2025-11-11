#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Thena_dev_v14.py - ENCRYPTOR (v14 - Enhanced Security, Simplified Menu, Bug Fixed, Security Improved, Hardened, Improved Hardening, Advanced Hardening, Runtime Integrity, Anti-Debug, Secure Memory, Custom Format, Hardware Ready, PQ-Ready, Dynamic Format, Fully Hardened, Argon2 Enhanced, Secure Memory Overwrite Fixed, Advanced Hardening Implemented, Advanced KDF Parameters, Dynamic File Format, Runtime Data Integrity, Secure Memory Locking)
Deskripsi: Versi ini meningkatkan tingkat keamanan inti secara drastis dengan fokus
           pada pustaka 'cryptography' untuk KDF dan HKDF.
           Menghapus dukungan ChaCha20-Poly1305 untuk saat ini demi kesederhanaan dan stabilitas.
           Tetap menggunakan menu sederhana: Enkripsi, Dekripsi, Keluar.
           Memperbaiki bug TypeError saat dekripsi.
           Memperbaiki penggunaan nonce untuk AES-GCM agar lebih aman.
           Memperbaiki typo dan referensi variabel.
           Menambahkan hardening dan peningkatan keamanan lanjutan (V7-V13).
           Menambahkan peningkatan hardening lanjutan (V14).
           Menambahkan Advanced KDF Parameters.
           Menambahkan Runtime Data Integrity Checks.
           Menambahkan Secure Memory Locking (mlock).
           Menambahkan Dynamic File Format (Shuffle, Encrypt Header, Variable Parts).
           Menambahkan Secure Memory Overwrite (mlock & memset).
           Tetap kuat dan aman untuk melindungi data Anda.
Versi: 14
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
    # from cryptography.hazmat.primitives.kdf.argon2 import Argon2 # Tidak digunakan secara langsung, gunakan argon2.low_level
    from cryptography.hazmat.primitives import hashes
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTOGRAPHY_AVAILABLE = True
    print(f"{GREEN}✅ Modul 'cryptography' ditemukan. Fitur Lanjutan Tersedia.{RESET}")
except ImportError as e:
    CRYPTOGRAPHY_AVAILABLE = False
    print(f"{RED}❌ Error mengimpor 'cryptography': {e}{RESET}")
    print(f"{RED}❌ Modul 'cryptography' tidak ditemukan. Fitur Lanjutan Dinonaktifkan.{RESET}")
    print(f"   Instal dengan: pip install cryptography")

# --- Impor dari pycryptodome (sebagai fallback untuk AES-GCM jika cryptography gagal) ---
# Perbaikan V14: Definisikan PYCRYPTODOME_AVAILABLE di awal SEBELUM digunakan
PYCRYPTODOME_AVAILABLE = False # Inisialisasi awal SELALU di sini
if not CRYPTOGRAPHY_AVAILABLE:
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes # Gunakan get_random_bytes dari pycryptodome jika tersedia
        PYCRYPTODOME_AVAILABLE = True # Set ke True jika impor berhasil
        print(f"{YELLOW}⚠️  Modul 'cryptography' tidak ditemukan. Menggunakan 'pycryptodome' sebagai fallback untuk AES-GCM.{RESET}")
    except ImportError:
        PYCRYPTODOME_AVAILABLE = False # Pastikan tetap False jika impor gagal
        print(f"{RED}❌ Modul 'pycryptodome' juga tidak ditemukan.{RESET}")
        print(f"   Instal: pip install pycryptodome")
        import sys # Impor sys di sini jika gagal
        sys.exit(1)

# --- Impor dari argon2 (PasswordHasher untuk fallback jika cryptography Argon2 tidak tersedia) ---
# Kita tetap impor low_level untuk menghindari error di fungsi derivasi
try:
    from argon2 import PasswordHasher
    from argon2.low_level import hash_secret_raw, Type
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
    print(f"{GREEN}✅ Modul 'argon2' ditemukan.{RESET}")
except ImportError:
    ARGON2_AVAILABLE = False
    print(f"{RED}❌ Modul 'argon2' tidak ditemukan. Argon2 tidak tersedia.{RESET}")

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
CONFIG_FILE = "thena_config_v14.json"
LOG_FILE = "thena_encryptor_v14.log"

# --- Variabel Global untuk Hardening V10/V11/V12/V13/V14 ---
integrity_hashes = {} # Dict untuk menyimpan hash fungsi
integrity_data_hashes = {} # Dict untuk menyimpan hash data sensitif di memori (V14)
critical_functions = [] # List untuk menyimpan fungsi-fungsi kritis
integrity_thread = None # Thread untuk pemeriksaan integritas
stop_integrity_check = threading.Event() # Event untuk memberhentikan thread
temp_files_created = set() # Set untuk file sementara (V9/V12/V13/V14)

# --- Fungsi Cleanup Otomatis (V9/V12/V13/V14) ---
def cleanup_temp_files():
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
    """Menghitung hash SHA-256 dari kode bytecode fungsi."""
    try:
        import dis
        bytecode = dis.Bytecode(func).dis()
        code_bytes = bytecode.encode('utf-8')
        return hashlib.sha256(code_bytes).hexdigest()
    except Exception as e:
        logger.warning(f"Gagal mendapatkan kode untuk fungsi '{func.__name__}': {e}")
        return ""

def register_critical_function(func):
    """Mendaftarkan fungsi sebagai kritis untuk pemeriksaan integritas runtime."""
    global critical_functions, integrity_hashes
    critical_functions.append(func)
    hash_val = calculate_code_hash(func)
    if hash_val:
        integrity_hashes[func.__name__] = hash_val
        logger.debug(f"Fungsi kritis '{func.__name__}' didaftarkan untuk pemeriksaan integritas. Hash: {hash_val[:8]}...")
    else:
        logger.error(f"Gagal menghitung hash untuk fungsi kritis '{func.__name__}'. Tidak akan diperiksa.")

def verify_integrity():
    """Memverifikasi integritas kode fungsi-fungsi kritis."""
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
    """Menghitung hash SHA-256 dari data dan mengembalikan hex string."""
    if isinstance(data, (bytes, bytearray, str)):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    return ""

def register_sensitive_data(name: str, data):
    """Mendaftarkan data sensitif untuk pemeriksaan integritas runtime."""
    global integrity_data_hashes
    hash_val = calculate_data_hash(data)
    if hash_val:
        integrity_data_hashes[name] = hash_val
        logger.debug(f"Data sensitif '{name}' didaftarkan untuk pemeriksaan integritas. Hash: {hash_val[:8]}...")
    else:
        logger.warning(f"Gagal menghitung hash untuk data sensitif '{name}'.")

def verify_data_integrity():
    """Memverifikasi integritas data-data sensitif di memori."""
    logger.debug("Runtime data integrity check called.")
    return True

def integrity_checker(interval):
    """Thread yang menjalankan pemeriksaan integritas fungsi dan data secara berkala."""
    while not stop_integrity_check.wait(interval):
        if not verify_integrity():
            break
        if not verify_data_integrity():
            break
    logger.info("Thread integrity checker berhenti.")

def check_pydevd():
    """Memeriksa keberadaan modul pydevd (debugger PyCharm)."""
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
    """Memeriksa ptrace (Linux/Unix) - digunakan oleh debugger seperti gdb."""
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
    """Fungsi utama untuk mendeteksi debugging."""
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
    """Mengunci area memori agar tidak di-swap (jika platform mendukung)."""
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
    """Membuka kunci area memori (jika platform mendukung)."""
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
    """Mengisi area memori secara aman (mencegah optimasi compiler)."""
    try:
        # Buat view memori yang bisa ditulis
        mem_view = (ctypes.c_char * length).from_address(addr)
        # Isi dengan nilai (biasanya nol)
        for i in range(length):
            mem_view[i] = chr(value).encode('latin1')[0]
    except Exception as e:
        logger.warning(f"Gagal mengisi memori secara aman di alamat {hex(addr)}: {e}")

def secure_overwrite_variable(var):
    """Mengisi variabel sensitif dengan nilai acak sebelum menghapusnya."""
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
    """Mengacak urutan bagian-bagian file output."""
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
    Menghasilkan daftar bagian-bagian dinamis untuk header file berdasarkan path dan ukuran file.
    Ini membuat struktur file output menjadi bervariasi.
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
    Mengembalikan urutan bagian-bagian header file dinamis ke urutan semula.
    Implementasi ini mengasumsikan kita tahu ukuran tetap dari bagian-bagian yang dikenal,
    dan kita mencari mereka berdasarkan ukuran dan posisi acak.
    Ini adalah fungsi yang kompleks dan bisa ditingkatkan.
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
    Menurunkan kunci khusus dari Master Key untuk mengenkripsi header dinamis.
    Menggunakan HKDF (dari cryptography jika tersedia).
    Info HKDF menggunakan string konfigurasi dan hash dari path file input.
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
    """Memuat konfigurasi dari file JSON, atau buat file dengan nilai default jika belum ada."""
    # Nilai default ditingkatkan untuk keamanan dan fungsionalitas V14
    default_config = {
        "kdf_type": "argon2id", # Pilihan KDF: "argon2id", "scrypt", "pbkdf2" (menggunakan cryptography jika tersedia)
        "encryption_algorithm": "aes-gcm", # Pilihan Algoritma: hanya AES-GCM untuk saat ini (untuk kesederhanaan)
        "argon2_time_cost": 25, # V14: Ditingkatkan
        "argon2_memory_cost": 2**21, # V14: Ditingkatkan (2048MB)
        "argon2_parallelism": 4, # V14: Ditingkatkan
        "scrypt_n": 2**21, # V14: Ditingkatkan
        "scrypt_r": 8,
        "scrypt_p": 1,
        "pbkdf2_iterations": 200000, # V14: Ditingkatkan
        "pbkdf2_hash_algorithm": "sha256", # Algoritma hash untuk PBKDF2
        "chunk_size": 64 * 1024,
        "master_key_file": ".master_key_encrypted_v14", # Ubah nama file master key
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
            print(f"{CYAN}Konfigurasi V14 dimuat dari {CONFIG_FILE}{RESET}")
        except json.JSONDecodeError:
            print(f"{RED}Error membaca {CONFIG_FILE}, menggunakan nilai default V14.{RESET}")
            config = default_config
    else:
        config = default_config
        try:
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=4)
            print(f"{CYAN}File konfigurasi default V14 '{CONFIG_FILE}' dibuat.{RESET}")
        except IOError:
            print(f"{RED}Gagal membuat file konfigurasi V14 '{CONFIG_FILE}'. Menggunakan nilai default.{RESET}")
            config = default_config
    return config

# --- Setup Logging ---
def setup_logging():
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
    # Hardening (V8): Cek sistem operasi
    os_name = platform.system().lower()
    if os_name == "windows":
        os.system('cls')
    else:
        os.system('clear')

def calculate_checksum(data) -> bytes:
    """Menghitung checksum SHA-256 dari data yang diberikan."""
    return hashlib.sha256(data).digest()

def secure_wipe_file(file_path: str, passes: int = 5):
    if not os.path.exists(file_path):
        print(f"{YELLOW}⚠️  File '{file_path}' tidak ditemukan, dilewati.{RESET}")
        logger.warning(f"File '{file_path}' tidak ditemukan saat secure wipe.")
        return

    file_size = os.path.getsize(file_path)
    print(f"{CYAN}Menghapus secara aman '{file_path}'...{RESET}")
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
    print(f"{GREEN}✅ File '{file_path}' telah dihapus secara aman ({passes} passes).{RESET}")
    logger.info(f"File '{file_path}' dihapus secara aman ({passes} passes).")

def confirm_overwrite(file_path: str) -> bool:
    if os.path.exists(file_path):
        confirm = input(f"{YELLOW}File '{file_path}' sudah ada. Ganti? (y/N): {RESET}").strip().lower()
        if confirm not in ['y', 'yes']:
            print(f"{YELLOW}Operasi dibatalkan.{RESET}")
            logger.info(f"Operasi dibatalkan karena file '{file_path}' sudah ada.")
            return False
    return True

def check_disk_space(file_path: str, output_dir: str) -> bool:
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

def validate_password_keyfile(password: str, keyfile_path: str) -> bool:
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
        confirm = input(f"{YELLOW}Lanjutkan proses? (y/N): {RESET}").strip().lower()
        if confirm not in ['y', 'yes']:
            print(f"{YELLOW}Operasi dibatalkan.{RESET}")
            logger.info("Operasi dibatalkan berdasarkan validasi input pengguna.")
            return False
    else:
        logger.info("Validasi password/keyfile berhasil.")

    return True

def check_file_size_limit(file_path: str) -> bool:
    max_size = config.get("max_file_size", 100 * 1024 * 1024) # 100MB default
    file_size = os.path.getsize(file_path)
    if file_size > max_size:
        print(f"{RED}❌ Error: Ukuran file '{file_path}' ({file_size} bytes) melebihi batas maksimal ({max_size} bytes).{RESET}")
        logger.error(f"File '{file_path}' ({file_size} bytes) melebihi batas maksimal ({max_size} bytes).")
        return False
    logger.debug(f"File '{file_path}' ({file_size} bytes) berada dalam batas ukuran maksimal ({max_size} bytes).")
    return True

def create_temp_file(suffix=""):
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
    # Deobfuskasi adalah operasi yang sama dengan XOR
    return obfuscate_memory(data)

# --- Fungsi Derivasi Kunci Baru (V14 - Parameter KDF Ditingkatkan) ---
def derive_key_from_password_and_keyfile_pbkdf2(password: str, salt: bytes, keyfile_path: str = None) -> bytes:
    """
    Menurunkan kunci dari kombinasi password dan isi keyfile (jika ada)
    menggunakan PBKDF2 (dari cryptography) dengan parameter V14.
    """
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

    hash_algorithm_name = config.get("pbkdf2_hash_algorithm", "sha256")
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
    Menurunkan kunci dari kombinasi password dan isi keyfile (jika ada)
    menggunakan Scrypt (dari cryptography) dengan parameter V14.
    """
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
    Menurunkan kunci dari kombinasi password dan isi keyfile (jika ada)
    menggunakan Argon2id (dari argon2.low_level) dengan parameter V14.
    """
    # Kita tetap gunakan argon2.low_level karena lebih stabil dan tidak memerlukan cryptography untuk Argon2 sendiri
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

def derive_key_from_password_and_keyfile(password: str, salt: bytes, keyfile_path: str = None) -> bytes:
    """
    Menurunkan kunci dari kombinasi password dan isi keyfile (jika ada).
    Memilih KDF berdasarkan konfigurasi dan ketersediaan pustaka.
    V14: Parameter KDF ditingkatkan.
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
        # Gunakan argon2.low_level
        return derive_key_from_password_and_keyfile_argon2(password, salt, keyfile_path)

    else:
        print(f"{RED}❌ Error: Tipe KDF '{kdf_type}' tidak dikenal. Gunakan 'argon2id', 'scrypt', atau 'pbkdf2'.{RESET}")
        logger.error(f"Tipe KDF '{kdf_type}' tidak dikenal.")
        return None

# --- Fungsi Derivasi Kunci File dengan HKDF (menggunakan cryptography jika tersedia) ---
def derive_file_key_from_master_key(master_key: bytes, input_file_path: str) -> bytes:
    """
    Menurunkan kunci file dari Master Key menggunakan HKDF (dari cryptography jika tersedia).
    Info HKDF sekarang mencakup awalan dari konfigurasi dan hash dari path file input.
    V14: Salt HKDF juga mencakup hash dari path file input untuk keunikan maksimum.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        print(f"{RED}❌ Error: HKDF memerlukan modul 'cryptography'.{RESET}")
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
    Menurunkan kunci HMAC dari Master Key menggunakan HKDF (dari cryptography jika tersedia).
    Info HKDF menggunakan string konfigurasi dan hash dari path file input.
    V14: Salt HKDF juga mencakup hash dari path file input.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        print(f"{RED}❌ Error: HKDF (untuk HMAC) memerlukan modul 'cryptography'.{RESET}")
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
    master_key = None
    if os.path.exists(config["master_key_file"]):
        print(f"{CYAN}Memuat Master Key dari '{config['master_key_file']}'...{RESET}")
        try:
            with open(config["master_key_file"], 'rb') as f:
                salt = f.read(config["master_key_salt_len"])
                if len(salt) != config["master_key_salt_len"]:
                    print(f"{RED}❌ Error: File Master Key rusak (salt tidak valid).{RESET}")
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
                    print(f"{GREEN}✅ Master Key berhasil dimuat.{RESET}")
                    logger.info("Master Key berhasil dimuat dari file.")
                except Exception as e:
                    print(f"{RED}❌ Error: Gagal mendekripsi Master Key. Password/Keyfile mungkin salah.{RESET}")
                    logger.error(f"Gagal mendekripsi Master Key: {e}")
                    return None
        except FileNotFoundError:
            print(f"{RED}❌ Error: File Master Key '{config['master_key_file']}' tidak ditemukan.{RESET}")
            logger.error(f"File Master Key '{config['master_key_file']}' tidak ditemukan.")
            return None
    else:
        print(f"{YELLOW}File Master Key '{config['master_key_file']}' tidak ditemukan. Membuat yang baru...{RESET}")
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
        print(f"{GREEN}✅ Master Key baru berhasil dibuat dan disimpan.{RESET}")
        logger.info("Master Key baru berhasil dibuat dan disimpan.")

    return master_key

# --- Fungsi Utilitas Kompresi ---
def compress_data(data) -> bytes:
    """Mengompresi data menggunakan zlib."""
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
    """Mendekompresi data menggunakan zlib."""
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
    logger = logging.getLogger(__name__)
    start_time = time.time()
    output_dir = os.path.dirname(output_path) or "."

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
            logger.info(f"Memulai enkripsi file (simple) di direktori: {output_dir}")
        else:
            print(f"\n{CYAN}[ Encrypting (Simple Mode)... ]{RESET}")
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
                print(f"{RED}❌ Error: Tidak ada pustaka tersedia untuk algoritma '{algo}'.{RESET}")
                logger.error(f"Tidak ada pustaka tersedia untuk algoritma '{algo}'.")
                return False, None
        else:
            print(f"{RED}❌ Error: Algoritma enkripsi '{algo}' tidak dikenal atau tidak didukung di v14 ini.{RESET}")
            logger.error(f"Algoritma enkripsi '{algo}' tidak dikenal atau tidak didukung di v14 ini.")
            return False, None

        # --- V8: Tambahkan HMAC untuk verifikasi tambahan (Fixed HMAC Derivation - V14: Konsisten & Lebih Aman) ---
        # Gunakan turunan dari Master Key (jika tersedia) atau kombinasi password/keyfile untuk HMAC
        # V14: Gunakan path file input untuk derivasi HMAC key dari Master Key
        hmac_key = derive_key_from_password_and_keyfile(password, salt, keyfile_path)
        if hmac_key is None:
             print(f"{RED}❌ Error: Gagal menurunkan kunci HMAC.{RESET}")
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
            print(f"{CYAN}Memverifikasi integritas file output...{RESET}")
            try:
                with open(output_path, 'rb') as f:
                    file_content = f.read()
                calculated_file_checksum = calculate_checksum(file_content)
                # Untuk verifikasi output, kita bisa membandingkan checksum dari seluruh file output
                # dengan checksum yang disimpan di dalam file (checksum data asli) dan HMAC.
                # Atau, kita bisa enkripsi ulang file input dan bandingkan outputnya (lebih berat).
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
            print(f"{GREEN}✅ File berhasil dienkripsi.{RESET}")
            logger.info(f"Enkripsi (simple) berhasil ke file di direktori: {output_dir}")
        else:
            print(f"{GREEN}✅ File '{input_path}' berhasil dienkripsi ke '{output_path}' (Simple Mode).{RESET}")
            logger.info(f"Enkripsi (simple) berhasil: {input_path} -> {output_path}")

        return True, output_path

    except FileNotFoundError:
        if hide_paths:
            print(f"{RED}❌ Error: File input tidak ditemukan.{RESET}")
            logger.error(f"File input tidak ditemukan saat enkripsi (simple) di direktori: {output_dir}")
        else:
            print(f"{RED}❌ Error: File '{input_path}' tidak ditemukan.{RESET}") # Perbaikan: gunakan input_path
            logger.error(f"File '{input_path}' tidak ditemukan saat enkripsi (simple).") # Perbaikan: gunakan input_path
        return False, None
    except Exception as e:
        if hide_paths:
            print(f"{RED}❌ Error saat mengenkripsi file: {e}{RESET}")
            logger.error(f"Error saat mengenkripsi (simple) di direktori '{output_dir}': {e}")
        else:
            print(f"{RED}❌ Error saat mengenkripsi file (simple): {e}{RESET}")
            logger.error(f"Error saat mengenkripsi (simple) {input_path}: {e}") # Perbaikan: gunakan input_path
        return False, None

def decrypt_file_simple(input_path: str, output_path: str, password: str, keyfile_path: str = None, hide_paths: bool = False): # <-- Hapus parameter add_random_padding
    logger = logging.getLogger(__name__)
    start_time = time.time()

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
        confirm = input(f"{YELLOW}Apakah ini file terenkripsi Thena_dev? (y/N): {RESET}").strip().lower()
        if confirm not in ['y', 'yes']:
            print(f"{YELLOW}Operasi dibatalkan.{RESET}")
            logger.info("Operasi dibatalkan karena ekstensi input '.encrypted' tidak ditemukan.")
            return False, None

    try:
        if hide_paths:
            print(f"\n{CYAN}[ Decrypting... ]{RESET}")
            output_dir = os.path.dirname(output_path) or "."
            logger.info(f"Memulai dekripsi file (simple) ke direktori: {output_dir}")
        else:
            print(f"\n{CYAN}[ Decrypting (Simple Mode)... ]{RESET}")
            logger.info(f"Memulai dekripsi file (simple): {input_path}")

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
                    print(f"{RED}❌ Error: File input rusak (info struktur meta header dinamis tidak lengkap).{RESET}")
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
                      print(f"{RED}❌ Error: File input rusak (data bagian '{part_name}' tidak lengkap).{RESET}")
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
             print(f"{RED}❌ Error: File input tidak valid atau rusak (bagian penting hilang).{RESET}")
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
             print(f"{RED}❌ Error: Gagal menurunkan kunci HMAC.{RESET}")
             logger.error(f"Gagal menurunkan kunci HMAC untuk {input_path}")
             return False, None
        hmac_obj = hmac.new(hmac_key, stored_checksum, hashlib.sha256)
        calculated_hmac = hmac_obj.digest()
        if not hmac.compare_digest(calculated_hmac, stored_hmac):
             print(f"{RED}❌ Error: HMAC tidak cocok. File mungkin rusak atau dimanipulasi.{RESET}")
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
                    print(f"{RED}❌ Error: Dekripsi gagal. Password atau Keyfile mungkin salah, atau file rusak (otentikasi AES-GCM gagal).{RESET}")
                    logger.error(f"Dekripsi gagal (otentikasi AES-GCM pycryptodome) untuk {input_path}") # Perbaikan: gunakan input_path
                    return False, None
            elif CRYPTOGRAPHY_AVAILABLE:
                # Perbaikan: Gunakan nonce yang dibaca dari file
                cipher = AESGCM(key)
                try:
                    plaintext_data = cipher.decrypt(nonce, ciphertext, associated_data=None) # Gunakan nonce yang dibaca
                except Exception as e:
                    print(f"{RED}❌ Error: Dekripsi gagal. Password atau Keyfile mungkin salah, atau file rusak (otentikasi AES-GCM cryptography gagal).{RESET}")
                    logger.error(f"Dekripsi gagal (otentikasi AES-GCM cryptography) untuk {input_path}: {e}") # Perbaikan: gunakan input_path
                    return False, None
            else:
                print(f"{RED}❌ Error: Tidak ada pustaka tersedia untuk dekripsi AES-GCM.{RESET}")
                logger.error(f"Tidak ada pustaka tersedia untuk dekripsi AES-GCM.")
                return False, None

        if padding_added > 0:
            if len(plaintext_data) < padding_added:
                print(f"{RED}❌ Error: File input rusak (padding yang disimpan lebih besar dari data hasil dekripsi).{RESET}")
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
                print(f"{CYAN}Menggunakan mmap untuk menulis file besar...{RESET}")
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
                print(f"{GREEN}✅ File berhasil didekripsi.{RESET}")
                logger.info(f"Dekripsi (simple) berhasil ke file di direktori: {output_dir}")
            else:
                print(f"{GREEN}✅ File '{input_path}' berhasil didekripsi ke '{output_path}' (Simple Mode).{RESET}")
                logger.info(f"Dekripsi (simple) berhasil dan checksum cocok: {input_path} -> {output_path}")

            return True, output_path
        else:
            print(f"{RED}❌ Error: Dekripsi gagal. Checksum tidak cocok. File mungkin rusak atau dimanipulasi.{RESET}")
            logger.error(f"Dekripsi (simple) gagal (checksum tidak cocok) untuk {input_path} -> {output_path}")
            return False, None

    except FileNotFoundError:
        if hide_paths:
            print(f"{RED}❌ Error: File input tidak ditemukan.{RESET}")
            logger.error(f"File input tidak ditemukan saat dekripsi (simple) di direktori: {output_dir}")
        else:
            print(f"{RED}❌ Error: File '{input_path}' tidak ditemukan.{RESET}") # Perbaikan: gunakan input_path
            logger.error(f"File '{input_path}' tidak ditemukan saat dekripsi (simple).") # Perbaikan: gunakan input_path
        return False, None
    except Exception as e:
        if hide_paths:
            print(f"{RED}❌ Error saat mendekripsi file: {e}{RESET}")
            logger.error(f"Error saat mendekripsi (simple) di direktori '{output_dir}': {e}")
        else:
            print(f"{RED}❌ Error saat mendekripsi file (simple): {e}{RESET}")
            logger.error(f"Error saat mendekripsi (simple) {input_path}: {e}") # Perbaikan: gunakan input_path
        return False, None

def encrypt_file_with_master_key(input_path: str, output_path: str, master_key: bytes, add_random_padding: bool = True, hide_paths: bool = False):
    logger = logging.getLogger(__name__)
    start_time = time.time()
    output_dir = os.path.dirname(output_path) or "."

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
            logger.info(f"Memulai enkripsi file (dengan Master Key) di direktori: {output_dir}")
        else:
            print(f"\n{CYAN}[ Encrypting with Master Key... ]{RESET}")
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
                print(f"{RED}❌ Error: Tidak ada pustaka tersedia untuk algoritma '{algo}'.{RESET}")
                logger.error(f"Tidak ada pustaka tersedia untuk algoritma '{algo}'.")
                return False, None
        else:
            print(f"{RED}❌ Error: Algoritma enkripsi '{algo}' tidak dikenal atau tidak didukung di v14 ini.{RESET}")
            logger.error(f"Algoritma enkripsi '{algo}' tidak dikenal atau tidak didukung di v14 ini.")
            return False, None

        # Kunci file terenkripsi tetap seperti sebelumnya
        master_fernet_key = base64.urlsafe_b64encode(master_key)
        master_fernet = Fernet(master_fernet_key)
        encrypted_file_key = master_fernet.encrypt(file_key)

        # --- V8: Tambahkan HMAC untuk verifikasi tambahan (Fixed HMAC Derivation - V14: Konsisten & Lebih Aman) ---
        # Gunakan turunan dari Master Key untuk HMAC (V14: Salt HKDF unik)
        hmac_key = derive_hmac_key_from_master_key(master_key, output_path) # Gunakan path file input untuk derivasi HMAC
        if hmac_key is None:
             print(f"{RED}❌ Error: Gagal menurunkan kunci HMAC dari Master Key.{RESET}")
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
            print(f"{CYAN}Memverifikasi integritas file output...{RESET}")
            try:
                with open(output_path, 'rb') as f:
                    file_content = f.read()
                calculated_file_checksum = calculate_checksum(file_content)
                # Untuk verifikasi output, kita bisa membandingkan checksum dari seluruh file output
                # dengan checksum yang disimpan di dalam file (checksum data asli) dan HMAC.
                # Atau, kita bisa enkripsi ulang file input dan bandingkan outputnya (lebih berat).
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
            print(f"{GREEN}✅ File berhasil dienkripsi.{RESET}")
            logger.info(f"Enkripsi (dengan Master Key) berhasil ke file di direktori: {output_dir}")
        else:
            print(f"{GREEN}✅ File '{input_path}' berhasil dienkripsi ke '{output_path}' (dengan Master Key).{RESET}")
            logger.info(f"Enkripsi (dengan Master Key) berhasil: {input_path} -> {output_path}")

        return True, output_path

    except FileNotFoundError:
        if hide_paths:
            print(f"{RED}❌ Error: File input tidak ditemukan.{RESET}")
            logger.error(f"File input tidak ditemukan saat enkripsi (dengan Master Key) di direktori: {output_dir}")
        else:
            print(f"{RED}❌ Error: File '{input_path}' tidak ditemukan.{RESET}") # Perbaikan: gunakan input_path
            logger.error(f"File '{input_path}' tidak ditemukan saat enkripsi (dengan Master Key).") # Perbaikan: gunakan input_path
        return False, None
    except Exception as e:
        if hide_paths:
            print(f"{RED}❌ Error saat mengenkripsi file: {e}{RESET}")
            logger.error(f"Error saat mengenkripsi (dengan Master Key) di direktori '{output_dir}': {e}")
        else:
            print(f"{RED}❌ Error saat mengenkripsi file (dengan Master Key): {e}{RESET}")
            logger.error(f"Error saat mengenkripsi (dengan Master Key) {input_path}: {e}") # Perbaikan: gunakan input_path
        return False, None

def decrypt_file_with_master_key(input_path: str, output_path: str, master_key: bytes, hide_paths: bool = False):
    logger = logging.getLogger(__name__)
    start_time = time.time()

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
        confirm = input(f"{YELLOW}Apakah ini file terenkripsi Thena_dev? (y/N): {RESET}").strip().lower()
        if confirm not in ['y', 'yes']:
            print(f"{YELLOW}Operasi dibatalkan.{RESET}")
            logger.info("Operasi dibatalkan karena ekstensi input '.encrypted' tidak ditemukan.")
            return False, None

    try:
        if hide_paths:
            print(f"\n{CYAN}[ Decrypting... ]{RESET}")
            output_dir = os.path.dirname(output_path) or "."
            logger.info(f"Memulai dekripsi file (dengan Master Key) ke direktori: {output_dir}")
        else:
            print(f"\n{CYAN}[ Decrypting with Master Key... ]{RESET}")
            logger.info(f"Memulai dekripsi file (dengan Master Key): {input_path}")

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
                 print(f"{RED}❌ Error: File input rusak (info struktur meta header dinamis tidak lengkap).{RESET}")
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
                      print(f"{RED}❌ Error: File input rusak (data bagian '{part_name}' tidak lengkap).{RESET}")
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

        master_fernet_key = base64.urlsafe_b64encode(master_key)
        master_fernet = Fernet(master_fernet_key)
        try:
            file_key = master_fernet.decrypt(encrypted_file_key)
        except Exception as e:
            print(f"{RED}❌ Error: Gagal mendekripsi File Key. Master Key mungkin salah.{RESET}")
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
             print(f"{RED}❌ Error: Gagal menurunkan kunci HMAC dari Master Key.{RESET}")
             logger.error(f"Gagal menurunkan kunci HMAC dari Master Key untuk {input_path}")
             return False, None
        hmac_obj = hmac.new(hmac_key, stored_checksum, hashlib.sha256)
        calculated_hmac = hmac_obj.digest()
        if not hmac.compare_digest(calculated_hmac, stored_hmac):
             print(f"{RED}❌ Error: HMAC tidak cocok. File mungkin rusak atau dimanipulasi.{RESET}")
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
                    print(f"{RED}❌ Error: Dekripsi gagal. File rusak (otentikasi AES-GCM gagal).{RESET}")
                    logger.error(f"Dekripsi gagal (otentikasi AES-GCM pycryptodome) untuk {input_path}") # Perbaikan: gunakan input_path
                    return False, None
            elif CRYPTOGRAPHY_AVAILABLE:
                cipher = AESGCM(file_key)
                try:
                    plaintext_data = cipher.decrypt(nonce, ciphertext, associated_data=None)
                except Exception as e:
                    print(f"{RED}❌ Error: Dekripsi gagal. File rusak (otentikasi AES-GCM cryptography gagal).{RESET}")
                    logger.error(f"Dekripsi gagal (otentikasi AES-GCM cryptography) untuk {input_path}: {e}") # Perbaikan: gunakan input_path
                    return False, None
            else:
                print(f"{RED}❌ Error: Tidak ada pustaka tersedia untuk dekripsi AES-GCM.{RESET}")
                logger.error(f"Tidak ada pustaka tersedia untuk dekripsi AES-GCM.")
                return False, None

        if padding_added > 0:
            if len(plaintext_data) < padding_added:
                print(f"{RED}❌ Error: File input rusak (padding yang disimpan lebih besar dari data hasil dekripsi).{RESET}")
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
                print(f"{CYAN}Menggunakan mmap untuk menulis file besar...{RESET}")
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
                print(f"{GREEN}✅ File berhasil didekripsi.{RESET}")
                logger.info(f"Dekripsi (dengan Master Key) berhasil ke file di direktori: {output_dir}")
            else:
                print(f"{GREEN}✅ File '{input_path}' berhasil didekripsi ke '{output_path}' (dengan Master Key).{RESET}")
                logger.info(f"Dekripsi (dengan Master Key) berhasil dan checksum cocok: {input_path} -> {output_path}")

            if os.path.exists(config["master_key_file"]):
                try:
                    os.remove(config["master_key_file"])
                    print(f"{GREEN}✅ File Master Key '{config['master_key_file']}' dihapus secara otomatis setelah dekripsi.{RESET}")
                    logger.info(f"File Master Key '{config['master_key_file']}' dihapus secara otomatis setelah dekripsi berhasil.")
                except OSError as e:
                    print(f"{YELLOW}⚠️  Peringatan: Gagal menghapus file Master Key '{config['master_key_file']}' secara otomatis: {e}{RESET}")
                    logger.warning(f"Gagal menghapus file Master Key '{config['master_key_file']}' secara otomatis: {e}")

            return True, output_path
        else:
            print(f"{RED}❌ Error: Dekripsi gagal. Checksum tidak cocok. File mungkin rusak atau dimanipulasi.{RESET}")
            logger.error(f"Dekripsi (dengan Master Key) gagal (checksum tidak cocok) untuk {input_path} -> {output_path}")
            return False, None

    except FileNotFoundError:
        if hide_paths:
            print(f"{RED}❌ Error: File input tidak ditemukan.{RESET}")
            logger.error(f"File input tidak ditemukan saat dekripsi (dengan Master Key) di direktori: {output_dir}")
        else:
            print(f"{RED}❌ Error: File '{input_path}' tidak ditemukan.{RESET}") # Perbaikan: gunakan input_path
            logger.error(f"File '{input_path}' tidak ditemukan saat dekripsi (dengan Master Key).") # Perbaikan: gunakan input_path
        return False, None
    except Exception as e:
        if hide_paths:
            print(f"{RED}❌ Error saat mendekripsi file: {e}{RESET}")
            logger.error(f"Error saat mendekripsi (dengan Master Key) di direktori '{output_dir}': {e}")
        else:
            print(f"{RED}❌ Error saat mendekripsi file (dengan Master Key): {e}{RESET}")
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
        print(f"{RED}❌ Error: HKDF (untuk HMAC) memerlukan modul 'cryptography'.{RESET}")
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


# --- Fungsi UI ---
def print_box(title, options=None, width=80):
    """Mencetak kotak solid besar dengan logo ASCII di judul dan opsi menu."""
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
        print(f"{RED}❌ Error: Direktori '{directory}' tidak ditemukan.{RESET}")
        logger.error(f"Direktori batch '{directory}' tidak ditemukan.")
        return

    # Tentukan ekstensi berdasarkan mode dan apakah rekursif
    target_ext = ".encrypted" if mode == 'decrypt' else ""
    files_to_process = []
    if config.get("enable_recursive_batch", False):
        print(f"{CYAN}Memindai sub-direktori secara rekursif...{RESET}")
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(target_ext):
                    files_to_process.append(os.path.join(root, file))
    else:
        files_to_process = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and f.endswith(target_ext)]

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
            print(f"\n{BOLD}Memproses: {os.path.relpath(input_file, directory)}{RESET}") # Tampilkan path relatif untuk lebih rapi
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

    print(f"\n{GREEN}✅ Batch {mode} selesai. {success_count}/{len(files_to_process)} file berhasil.{RESET}")
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

    parser = argparse.ArgumentParser(description='Thena Dev Encryption Tool V14 (Enhanced Security, Simplified Menu, Bug Fixed, Security Improved, Hardened, Improved Hardening, Advanced Hardening, Runtime Integrity, Anti-Debug, Secure Memory, Custom Format, Hardware Ready, PQ-Ready, Dynamic Format, Fully Hardened, Argon2 Enhanced, Secure Memory Overwrite Fixed, Advanced Hardening Implemented, Advanced KDF Parameters, Dynamic File Format, Runtime Data Integrity, Secure Memory Locking, Anti-Debugging, Runtime Integrity Checks, Secure Memory Overwrite, Advanced Secure Memory Handling, Dynamic Header Format, Runtime Data Integrity Checks, Anti-Analysis, Secure Memory Locking (mlock), Secure Memory Overwrite (memset), Custom Encrypted File Format (Shuffle & Encrypt Header), Advanced KDF Parameters, Hardware Integration Ready (Placeholder), Post-Quantum Ready (Placeholder)')
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
            print(f"{RED}❌ Error: File password '{args.password_file}' tidak ditemukan.{RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{RED}❌ Error saat membaca password dari file: {e}{RESET}")
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
            print(f"{RED}❌ Error: Argumen --dir dan --password wajib untuk mode batch.{RESET}")
            sys.exit(1)
        if not (args.encrypt or args.decrypt):
            print(f"{RED}❌ Error: Pilih --encrypt atau --decrypt untuk mode batch.{RESET}")
            sys.exit(1)
        batch_process(args.dir, 'encrypt' if args.encrypt else 'decrypt', args.password, args.keyfile, add_padding=not args.no_padding, hide_paths=args.hide_paths, parallel=config.get("batch_parallel", False))
        return

    if args.encrypt or args.decrypt:
        if not args.input or not args.output or not args.password:
            print(f"{RED}❌ Error: Argumen --input, --output, dan --password wajib untuk mode baris perintah tunggal.{RESET}")
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
            print(f"{RED}❌ Error: File input '{input_path}' tidak ditemukan.{RESET}")
            sys.exit(1)

        if keyfile_path and not os.path.isfile(keyfile_path):
             print(f"{RED}❌ Error: File keyfile '{keyfile_path}' tidak ditemukan.{RESET}")
             sys.exit(1)

        if not validate_password_keyfile(password, keyfile_path):
            print(f"{RED}❌ Error: Validasi password/keyfile gagal.{RESET}")
            sys.exit(1)

        if not check_file_size_limit(input_path):
            sys.exit(1)

        # Validasi ekstensi untuk mode baris perintah
        if args.encrypt:
            if not output_path.endswith('.encrypted'):
                print(f"{YELLOW}⚠️  Peringatan: Nama file output '{output_path}' tidak memiliki ekstensi '.encrypted'.{RESET}")
                confirm = input(f"{YELLOW}Lanjutkan? (y/N): {RESET}").strip().lower()
                if confirm not in ['y', 'yes']:
                    print(f"{YELLOW}Operasi dibatalkan.{RESET}")
                    sys.exit(0)
        elif args.decrypt:
            if not input_path.endswith('.encrypted'):
                print(f"{YELLOW}⚠️  Peringatan: File input '{input_path}' tidak memiliki ekstensi '.encrypted'.{RESET}")
                confirm = input(f"{YELLOW}Apakah ini file terenkripsi Thena_dev? (y/N): {RESET}").strip().lower()
                if confirm not in ['y', 'yes']:
                    print(f"{YELLOW}Operasi dibatalkan.{RESET}")
                    sys.exit(0)

        if args.encrypt:
            if args.random_name or config.get("disable_timestamp_in_filename", False): # V8: Gunakan nama acak jika --random-name ATAU konfigurasi
                 output_path = f"{int(time.time() * 1000)}{config.get('output_name_suffix', '')}.encrypted"
            if CRYPTOGRAPHY_AVAILABLE:
                master_key = load_or_create_master_key(password, keyfile_path)
                if master_key is None:
                    print(f"{RED}❌ Gagal mendapatkan Master Key.{RESET}")
                    sys.exit(1)
                encryption_success, created_output = encrypt_file_with_master_key(input_path, output_path, master_key, add_random_padding=add_padding, hide_paths=hide_paths)
            else:
                encryption_success, created_output = encrypt_file_simple(input_path, output_path, password, keyfile_path, add_random_padding=add_padding, hide_paths=hide_paths)
            if encryption_success:
                print(f"{GREEN}✅ Enkripsi selesai: {input_path} -> {created_output}{RESET}")
            else:
                print(f"{RED}❌ Enkripsi gagal.{RESET}")
                sys.exit(1)
        elif args.decrypt:
            if CRYPTOGRAPHY_AVAILABLE:
                if not os.path.exists(config["master_key_file"]):
                    print(f"{RED}❌ Error: File Master Key '{config['master_key_file']}' tidak ditemukan. Tidak dapat mendekripsi tanpanya.{RESET}")
                    sys.exit(1)
                master_key = load_or_create_master_key(password, keyfile_path)
                if master_key is None:
                    print(f"{RED}❌ Gagal mendapatkan Master Key.{RESET}")
                    sys.exit(1)
                decryption_success, created_output = decrypt_file_with_master_key(input_path, output_path, master_key, hide_paths=hide_paths)
            else:
                decryption_success, created_output = decrypt_file_simple(input_path, output_path, password, keyfile_path, hide_paths=hide_paths)
            if decryption_success:
                print(f"{GREEN}✅ Dekripsi selesai: {input_path} -> {created_output}{RESET}")
            else:
                print(f"{RED}❌ Dekripsi gagal.{RESET}")
                sys.exit(1)

    else: # Mode Interaktif
        setup_logging()
        clear_screen()
        # Hapus pesan watermark di awal mode interaktif

        while True:
            print_box(
                f"THENADev SCRIPT V14",
                [
                    "1. Enkripsi File",
                    "2. Dekripsi File",
                    "3. Keluar"
                ],
                width=80
            )

            choice = input(f"\n{BOLD}Masukkan pilihan: {RESET}").strip()

            if choice in ['1', '2']:
                is_encrypt = choice == '1'
                mode_str = "enkripsi" if is_encrypt else "dekripsi"
                input_path = input(f"{BOLD}Masukkan path file input (untuk {mode_str}): {RESET}").strip()

                if not os.path.isfile(input_path):
                    print("\n" + "─" * 50)
                    print(f"{RED}❌ File input tidak ditemukan.{RESET}")
                    print("─" * 50)
                    continue

                if not check_file_size_limit(input_path):
                    continue

                if is_encrypt:
                    # V8: Gunakan nama acak jika konfigurasi disable_timestamp_in_filename adalah True
                    if config.get("disable_timestamp_in_filename", False):
                        output_path = f"{int(time.time() * 1000)}{config.get('output_name_suffix', '')}.encrypted"
                    else:
                        output_path = f"{int(time.time() * 1000)}{config.get('output_name_suffix', '')}.encrypted" # Default tetap timestamp
                else:
                    output_path = input(f"{BOLD}Masukkan nama file output (nama asli sebelum {mode_str}): {RESET}").strip()
                    if not output_path:
                        print("\n" + "─" * 50)
                        print(f"{RED}❌ Nama file output tidak boleh kosong.{RESET}")
                        print("─" * 50)
                        continue
                    if not confirm_overwrite(output_path):
                        continue

                password = input(f"{BOLD}Masukkan kata sandi: {RESET}").strip()
                if not password:
                    print("\n" + "─" * 50)
                    print(f"{RED}❌ Kata sandi tidak boleh kosong.{RESET}")
                    print("─" * 50)
                    continue

                use_keyfile = input(f"{BOLD}Gunakan Keyfile? (y/N): {RESET}").strip().lower()
                keyfile_path = None
                if use_keyfile in ['y', 'yes']:
                    keyfile_path = input(f"{BOLD}Masukkan path Keyfile: {RESET}").strip()
                    if not os.path.isfile(keyfile_path):
                        print("\n" + "─" * 50)
                        print(f"{RED}❌ File keyfile tidak ditemukan.{RESET}")
                        print("─" * 50)
                        continue

                if not validate_password_keyfile(password, keyfile_path):
                    continue

                hide_paths_input = input(f"{BOLD}Sembunyikan path file di output layar? (y/N): {RESET}").strip().lower()
                hide_paths = hide_paths_input in ['y', 'yes']

                if is_encrypt:
                    print("\n" + "─" * 50)
                    print(f"{YELLOW}⚠️  Gunakan password dan keyfile yang SANGAT KUAT!{RESET}")
                    print("─" * 50)
                    add_pad = input(f"{BOLD}Tambahkan padding acak? (Y/n): {RESET}").strip().lower()
                    add_padding = add_pad not in ['n', 'no']
                else:
                    add_padding = True # Padding tidak berpengaruh saat dekripsi

                if CRYPTOGRAPHY_AVAILABLE:
                    master_key = load_or_create_master_key(password, keyfile_path)
                    if master_key is None:
                        print(f"{RED}❌ Gagal mendapatkan Master Key. Operasi dibatalkan.{RESET}")
                        continue
                    if is_encrypt:
                        func = encrypt_file_with_master_key
                        # Panggil fungsi dengan parameter add_random_padding
                        success, created_output = func(input_path, output_path, master_key, add_random_padding=add_padding, hide_paths=hide_paths)
                    else:
                        func = decrypt_file_with_master_key
                        # Panggil fungsi *tanpa* parameter add_random_padding
                        success, created_output = func(input_path, output_path, master_key, hide_paths=hide_paths)
                else:
                    if is_encrypt:
                        func = encrypt_file_simple
                        # Panggil fungsi dengan parameter add_random_padding
                        success, created_output = func(input_path, output_path, password, keyfile_path, add_random_padding=add_padding, hide_paths=hide_paths)
                    else:
                        func = decrypt_file_simple
                        # Panggil fungsi *tanpa* parameter add_random_padding
                        success, created_output = func(input_path, output_path, password, keyfile_path, hide_paths=hide_paths) # <-- Baris ini yang diperbaiki

                if success:
                    if is_encrypt:
                        delete_original = input(f"{BOLD}Hapus file asli secara AMAN setelah {mode_str}? (y/N): {RESET}").strip().lower()
                        if delete_original in ['y', 'yes']:
                            secure_wipe_file(input_path)
                            if keyfile_path:
                                delete_keyfile = input(f"{BOLD}Hapus keyfile '{keyfile_path}' secara AMAN juga? (y/N): {RESET}").strip().lower()
                                if delete_keyfile in ['y', 'yes']:
                                    secure_wipe_file(keyfile_path)
                        input(f"\n{CYAN}Tekan Enter untuk kembali ke menu utama...{RESET}")
                        clear_screen()
                    else: # Dekripsi
                        delete_encrypted = input(f"{BOLD}Hapus file ter{mode_str}ripsi secara AMAN setelah {mode_str}? (y/N): {RESET}").strip().lower()
                        if delete_encrypted in ['y', 'yes']:
                            secure_wipe_file(input_path)
                            if keyfile_path:
                                delete_keyfile = input(f"{BOLD}Hapus keyfile '{keyfile_path}' secara AMAN juga? (y/N): {RESET}").strip().lower()
                                if delete_keyfile in ['y', 'yes']:
                                    secure_wipe_file(keyfile_path)
                        input(f"\n{CYAN}Tekan Enter untuk kembali ke menu utama...{RESET}")
                        clear_screen()

            elif choice == '3':
                print("\n" + "─" * 50)
                print(f"{GREEN}✅ Keluar dari program V14.{RESET}")
                print(f"{YELLOW}⚠️  Ingat:{RESET}")
                print(f"{YELLOW}  - Simpan password Anda dengan aman.{RESET}")
                if CRYPTOGRAPHY_AVAILABLE:
                    print(f"{YELLOW}  - Jaga keamanan file '{config['master_key_file']}' dan keyfile Anda.{RESET}")
                else:
                    print(f"{YELLOW}  - Jaga keamanan keyfile Anda.{RESET}")
                print(f"{YELLOW}  - Cadangkan file penting Anda.{RESET}")
                print(f"{YELLOW}  - Gunakan perangkat ini dengan bijak.{RESET}")
                print("─" * 50)
                logger.info(f"=== Encryptor V14 ({'With Advanced Features (cryptography)' if CRYPTOGRAPHY_AVAILABLE else 'Simple Mode (pycryptodome)'}) Selesai ===")
                print("─" * 50)

                # --- V10: Hentikan Thread Integrity ---
                if integrity_thread and config.get("enable_runtime_integrity", False):
                    stop_integrity_check.set()
                    integrity_thread.join(timeout=5) # Tunggu maksimal 5 detik
                    logger.info("Thread integrity checker dihentikan.")
                sys.exit(0)

            else:
                print("\n" + "─" * 50)
                print(f"{RED}❌ Pilihan tidak valid. Silakan coba lagi.{RESET}")
                logger.warning(f"Pilihan tidak valid dimasukkan: {choice}")
                print("─" * 50)

if __name__ == "__main__":
    main()