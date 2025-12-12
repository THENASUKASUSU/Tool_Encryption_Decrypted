#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Versi: 19.0 (Refactored)
Alat enkripsi/dekripsi file yang aman dengan dukungan streaming.
"""
import argparse
import gc
import logging
import os
import secrets
import sys
from typing import Optional, Union

# --- Konfigurasi ---
STREAM_FALLBACK_THRESHOLD = 100 * 1024 * 1024  # 100MB
LOG_FILE = "enkripsi.log"
KEY_ITERATIONS = 390000
KEY_LENGTH = 32  # 256-bit key
SALT_LENGTH = 16
NONCE_LENGTH = 12  # 96-bit nonce for AES-GCM
TAG_LENGTH = 16  # 128-bit tag for AES-GCM
CHUNK_SIZE = 64 * 1024

# --- Pengecekan Library ---
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    PYCRYPTODOME_AVAILABLE = True
except ImportError:
    PYCRYPTODOME_AVAILABLE = False

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

logger = logging.getLogger(__name__)


# --- B.3: Logging & CLI ---
def setup_logging(hide_terminal: bool = False, level: str = "INFO"):
    """Mengatur logging ke file dan (opsional) ke terminal."""
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Hapus handler yang ada untuk menghindari duplikasi
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    handlers = [logging.FileHandler(LOG_FILE, mode="w")]
    if not hide_terminal:
        handlers.append(logging.StreamHandler(sys.stdout))

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )


# --- B.4: Anti-debugging ---
def detect_debugging():
    """Mendeteksi lingkungan debugging sederhana dan menaikkan RuntimeError."""
    # Pengecekan modul debugger umum
    if "pydevd" in sys.modules or "pydevd_pycharm" in sys.modules:
        logger.critical("Lingkungan debugging terdeteksi (PyDevd).")
        raise RuntimeError("Debugging environment detected")
    # Pengecekan ptrace sederhana untuk Linux
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/status") as f:
                if any(
                    line.startswith("TracerPid:") and int(line.split()[1]) != 0
                    for line in f
                ):
                    logger.critical("Lingkungan debugging terdeteksi (TracerPID).")
                    raise RuntimeError("Debugging environment detected")
        except (IOError, ValueError):
            # Abaikan jika tidak bisa membaca file status (misalnya, karena izin)
            pass


# --- B.5: Secure memory overwrite ---
def secure_overwrite_variable(obj: Union[bytearray, memoryview, bytes, str]):
    """
    Menimpa variabel sensitif di memori.
    Peringatan: Tidak ada jaminan penghapusan total pada semua platform untuk tipe immutable.
    """
    try:
        if isinstance(obj, (bytearray, memoryview)):
            # Tipe mutable bisa ditimpa di tempat
            obj[:] = b"\x00" * len(obj)
        elif isinstance(obj, (bytes, str)):
            # Tipe immutable (bytes/str) tidak bisa diubah.
            # Kita hanya bisa menghapus referensi dan berharap garbage collector membersihkannya.
            # Komentar ini berfungsi sebagai penjelasan yang diminta.
            pass
    finally:
        # Hapus referensi dan panggil garbage collector
        del obj
        gc.collect()


# --- Fungsi Inti ---
def derive_key(
    password: str, salt: bytes, keyfile_path: Optional[str] = None
) -> bytes:
    """Mendapatkan kunci dari password dan keyfile menggunakan PBKDF2."""
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("'cryptography' diperlukan untuk derivasi kunci.")

    password_bytes = password.encode("utf-8")
    keyfile_bytes = b""
    if keyfile_path:
        if not os.path.isfile(keyfile_path):
            raise FileNotFoundError(f"File keyfile tidak ditemukan: {keyfile_path}")
        with open(keyfile_path, "rb") as kf:
            keyfile_bytes = kf.read()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=KEY_ITERATIONS,
    )
    return kdf.derive(password_bytes + keyfile_bytes)


def encrypt(
    input_path: str, output_path: str, password: str, keyfile_path: Optional[str]
):
    """
    Enkripsi file, memilih metode streaming jika PyCryptodome tersedia,
    jika tidak, gunakan fallback in-memory.
    """
    salt = secrets.token_bytes(SALT_LENGTH)
    key = derive_key(password, salt, keyfile_path)

    try:
        input_size = os.path.getsize(input_path)
        use_fallback = not PYCRYPTODOME_AVAILABLE

        if use_fallback:
            logger.warning("PyCryptodome tidak tersedia. Menggunakan fallback in-memory.")
            if input_size > STREAM_FALLBACK_THRESHOLD:
                raise MemoryError(
                    f"File > {STREAM_FALLBACK_THRESHOLD // 1024**2}MB. PyCryptodome diperlukan untuk streaming."
                )

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_out.write(salt)
            if use_fallback:
                # Fallback in-memory dengan 'cryptography'
                nonce = secrets.token_bytes(NONCE_LENGTH)
                f_out.write(nonce)
                aesgcm = AESGCM(key)
                ciphertext_and_tag = aesgcm.encrypt(nonce, f_in.read(), None)
                f_out.write(ciphertext_and_tag)
            else:
                # Streaming dengan PyCryptodome
                nonce = get_random_bytes(NONCE_LENGTH)
                f_out.write(nonce)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    f_out.write(cipher.encrypt(chunk))
                f_out.write(cipher.digest())
    finally:
        # Selalu bersihkan kunci dari memori
        secure_overwrite_variable(key)


def decrypt(
    input_path: str, output_path: str, password: str, keyfile_path: Optional[str]
):
    """
    Dekripsi file, memilih metode streaming jika PyCryptodome tersedia,
    jika tidak, gunakan fallback in-memory.
    """
    key = None
    try:
        input_size = os.path.getsize(input_path)
        use_fallback = not PYCRYPTODOME_AVAILABLE

        if use_fallback:
            logger.warning("PyCryptodome tidak tersedia. Menggunakan fallback in-memory.")
            if input_size > STREAM_FALLBACK_THRESHOLD + SALT_LENGTH + NONCE_LENGTH:
                raise MemoryError(
                    f"File > {STREAM_FALLBACK_THRESHOLD // 1024**2}MB. PyCryptodome diperlukan untuk streaming."
                )

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            salt = f_in.read(SALT_LENGTH)
            nonce = f_in.read(NONCE_LENGTH)
            key = derive_key(password, salt, keyfile_path)

            if use_fallback:
                # Fallback in-memory dengan 'cryptography'
                aesgcm = AESGCM(key)
                ciphertext_and_tag = f_in.read()
                plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
                f_out.write(plaintext)
            else:
                # Streaming dengan PyCryptodome
                tag_pos = input_size - TAG_LENGTH
                f_in.seek(tag_pos)
                tag = f_in.read(TAG_LENGTH)
                f_in.seek(SALT_LENGTH + NONCE_LENGTH)

                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

                ciphertext_size = input_size - SALT_LENGTH - NONCE_LENGTH - TAG_LENGTH
                bytes_read = 0
                while bytes_read < ciphertext_size:
                    read_size = min(CHUNK_SIZE, ciphertext_size - bytes_read)
                    chunk = f_in.read(read_size)
                    f_out.write(cipher.decrypt(chunk))
                    bytes_read += len(chunk)

                cipher.verify(tag)

    except (ValueError, InvalidTag):
        # Hapus file output yang mungkin sebagian ditulis jika verifikasi gagal
        if os.path.exists(output_path):
            os.remove(output_path)
        # Naikkan kembali error dengan pesan yang lebih jelas
        raise ValueError(
            "Integritas file tidak dapat diverifikasi. File mungkin rusak atau kunci salah."
        )
    finally:
        # Selalu bersihkan kunci dari memori
        if key:
            secure_overwrite_variable(key)


def main():
    """Fungsi utama untuk menjalankan alat enkripsi/dekripsi dari baris perintah."""
    parser = argparse.ArgumentParser(
        description="Alat enkripsi/dekripsi file aman menggunakan AES-GCM.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true", help="Enkripsi file input.")
    group.add_argument("-d", "--decrypt", action="store_true", help="Dekripsi file input.")

    parser.add_argument("-i", "--input", required=True, help="Path file input.")
    parser.add_argument("-o", "--output", required=True, help="Path file output.")
    parser.add_argument("-p", "--password", required=True, help="Password untuk derivasi kunci.")
    parser.add_argument(
        "-k", "--keyfile", help="(Opsional) Path ke keyfile untuk keamanan tambahan."
    )

    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument(
        "--quiet",
        action="store_true",
        help="Jangan tampilkan output ke terminal (hanya log ke file).",
    )
    log_group.add_argument("--hide-logs", action="store_true", help="Alias untuk --quiet.")

    parser.add_argument(
        "--hide-paths", action="store_true", help="Sembunyikan path file dari pesan log INFO."
    )

    args = parser.parse_args()

    # Atur logging berdasarkan flag dari argumen
    setup_logging(hide_terminal=args.quiet or args.hide_logs)

    try:
        # Jalankan deteksi debugger
        detect_debugging()

        # Siapkan path untuk logging yang aman
        if args.hide_paths:
            log_input, log_output = "file input", "file output"
        else:
            log_input, log_output = f"'{args.input}'", f"'{args.output}'"

        if args.encrypt:
            logger.info(f"Memulai enkripsi {log_input} ke {log_output}...")
            encrypt(args.input, args.output, args.password, args.keyfile)
            logger.info("Enkripsi berhasil.")
        elif args.decrypt:
            logger.info(f"Memulai dekripsi {log_input} ke {log_output}...")
            decrypt(args.input, args.output, args.password, args.keyfile)
            logger.info("Dekripsi berhasil.")

    except (FileNotFoundError, MemoryError, ValueError, ImportError, RuntimeError) as e:
        logger.error(f"Operasi gagal: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Terjadi kesalahan yang tidak terduga: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    if not (PYCRYPTODOME_AVAILABLE or CRYPTOGRAPHY_AVAILABLE):
        print(
            "FATAL: PyCryptodome atau cryptography harus diinstal untuk menjalankan skrip ini.",
            file=sys.stderr,
        )
        sys.exit(1)
    main()