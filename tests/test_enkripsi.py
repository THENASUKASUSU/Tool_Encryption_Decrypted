import os
import subprocess
import sys
import pytest

# Tambahkan direktori root proyek ke path agar bisa mengimpor Enkripsi
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Enkripsi import (
    encrypt,
    decrypt,
    PYCRYPTODOME_AVAILABLE,
)

PASSWORD = "testpassword123"
SALT = os.urandom(16)


# C.2 test_roundtrip_small_file()
def test_roundtrip_small_file(tmp_path):
    """Tes enkripsi dan dekripsi file kecil dan memastikan isinya sama."""
    input_file = tmp_path / "small_test.txt"
    encrypted_file = tmp_path / "small_test.enc"
    decrypted_file = tmp_path / "small_test.dec"
    original_content = os.urandom(1024)  # 1KB file
    input_file.write_bytes(original_content)

    # Enkripsi
    encrypt(str(input_file), str(encrypted_file), PASSWORD, None)
    assert encrypted_file.exists()

    # Dekripsi
    decrypt(str(encrypted_file), str(decrypted_file), PASSWORD, None)
    assert decrypted_file.exists()

    # Verifikasi
    decrypted_content = decrypted_file.read_bytes()
    assert original_content == decrypted_content


# C.2 test_streaming_large_file()
@pytest.mark.skipif(
    not PYCRYPTODOME_AVAILABLE,
    reason="PyCryptodome tidak tersedia; tes streaming dilewati.",
)
def test_streaming_large_file(tmp_path):
    """Tes enkripsi dan dekripsi file besar untuk memastikan jalur streaming berfungsi."""
    input_file = tmp_path / "large_test.bin"
    encrypted_file = tmp_path / "large_test.enc"
    decrypted_file = tmp_path / "large_test.dec"
    original_content = os.urandom(5 * 1024 * 1024)  # 5MB file
    input_file.write_bytes(original_content)

    # Enkripsi (akan menggunakan streaming jika PyCryptodome tersedia)
    encrypt(str(input_file), str(encrypted_file), PASSWORD, None)
    assert encrypted_file.exists()

    # Dekripsi (akan menggunakan streaming jika PyCryptodome tersedia)
    decrypt(str(encrypted_file), str(decrypted_file), PASSWORD, None)
    assert decrypted_file.exists()

    # Verifikasi
    decrypted_content = decrypted_file.read_bytes()
    assert original_content == decrypted_content


# C.2 test_quiet_flag()
def test_quiet_flag(tmp_path):
    """
    Tes flag --quiet dan memastikan tidak ada output yang dicetak ke stdout.
    """
    input_file = tmp_path / "quiet_test.txt"
    encrypted_file = tmp_path / "quiet_test.enc"
    original_content = b"test content"
    input_file.write_bytes(original_content)

    # Jalankan skrip sebagai subprocess untuk menangkap stdout
    command = [
        sys.executable,
        os.path.join(
            os.path.dirname(__file__), "..", "Enkripsi.py"
        ),  # Path ke skrip
        "--encrypt",
        "--input",
        str(input_file),
        "--output",
        str(encrypted_file),
        "--password",
        PASSWORD,
        "--quiet",
    ]

    result = subprocess.run(
        command, capture_output=True, text=True, check=False
    )

    # Pastikan tidak ada output di stdout dan tidak ada error di stderr
    assert (
        result.stdout == ""
    ), f"Stdout seharusnya kosong dengan flag --quiet, tapi berisi: {result.stdout}"
    assert (
        result.stderr == ""
    ), f"Stderr seharusnya kosong, tapi berisi: {result.stderr}"
    assert result.returncode == 0, "Proses seharusnya keluar dengan kode 0 (sukses)"
