# Thena_dev Encryption Tool

## Introduction

Thena_dev is a powerful command-line encryption tool written in Python. It provides a secure and flexible way to encrypt and decrypt files using modern, industry-standard cryptographic libraries. The tool is designed with a focus on security, performance, and ease of use, offering both interactive and command-line modes to suit different workflows.

At its core, Thena_dev employs robust encryption algorithms like AES-256-GCM and ChaCha20-Poly1305, ensuring that your data is protected with authenticated encryption. It also supports multiple Key Derivation Functions (KDFs), including Argon2id, scrypt, and PBKDF2, to securely derive encryption keys from user-provided passwords and keyfiles.

## Features

- **Multiple KDFs**: Choose between Argon2id, scrypt, and PBKDF2 for deriving keys from passwords.
- **Strong Encryption**: Implements AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, and AES-SIV for authenticated encryption.
- **Hybrid Encryption**: Supports a hybrid encryption scheme using RSA and Curve25519 for an additional layer of security.
- **Master Key System**: Supports the use of a master key for an additional layer of security.
- **Interactive and CLI Modes**: An easy-to-use interactive menu for beginners and a full-featured command-line interface for scripting and automation.
- **Secure File Wiping**: A utility to securely overwrite and delete original files after encryption or decryption.
- **Batch Processing**: Encrypt or decrypt entire directories of files at once.
- **Advanced Hardening**: Includes runtime integrity checks, anti-debugging measures, and secure memory handling to protect against advanced threats.
- **Compression**: Option to compress files with zlib before encryption to save space.
- **Customizable Configuration**: A JSON configuration file allows for fine-tuning of cryptographic parameters and tool behavior.

## Requirements

- Python 3.6+
- `cryptography`
- `pycryptodome`
- `argon2-cffi`
- `miscreant`
- `pynacl`

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/THENASUKASUSU/thena-dev.git
    cd thena-dev
    ```

2.  **Install the required dependencies:**
    ```bash
    pip install cryptography pycryptodome argon2-cffi miscreant pynacl
    ```

## Configuration

The tool uses a `thena_config_v18.json` file to manage its settings. If this file is not found, it will be created with default values upon the first run. You can modify this file to customize the tool's behavior.

Key configuration options include:

-   `kdf_type`: The Key Derivation Function to use (`argon2id`, `scrypt`, or `pbkdf2`).
-   `preferred_algorithm_priority`: A list of symmetric encryption algorithms to be used, in order of preference.
-   `argon2_time_cost`, `argon2_memory_cost`, `argon2_parallelism`: Parameters for the Argon2id KDF.
-   `enable_compression`: Set to `true` to enable zlib compression before encryption.
-   `log_level`: The logging level (`INFO`, `DEBUG`, `WARNING`, `ERROR`).

## Usage

### Interactive Mode

To start the tool in interactive mode, run the script without any arguments:

```bash
python3 Thena_dev_v19.py
```

You will be guided through a menu to select an operation (encrypt or decrypt) and provide the necessary inputs.

### Command-Line Interface (CLI)

#### Simple Encryption

```bash
python3 Thena_dev_v19.py --encrypt -i <input_file> -o <output_file> -p <password>
```

#### Simple Decryption

```bash
python3 Thena_dev_v19.py --decrypt -i <input_file> -o <output_file> -p <password>
```

#### Encryption with a Keyfile

For enhanced security, you can use a keyfile in addition to a password.

```bash
python3 Thena_dev_v19.py --encrypt -i <input_file> -o <output_file> -p <password> -k <keyfile_path>
```

#### Decryption with a Keyfile

```bash
python3 Thena_dev_v19.py --decrypt -i <input_file> -o <output_file> -p <password> -k <keyfile_path>
```

#### Batch Processing

To encrypt all files in a directory:

```bash
python3 Thena_dev_v19.py --batch --encrypt --dir <directory_path> -p <password>
```

To decrypt all `.encrypted` files in a directory:

```bash
python3 Thena_dev_v19.py --batch --decrypt --dir <directory_path> -p <password>
```

### All CLI Arguments

-   `--encrypt`: Encrypt a file.
-   `--decrypt`: Decrypt a file.
-   `--batch`: Process a directory of files.
-   `--dir <directory>`: The directory to process in batch mode.
-   `-i, --input <input_file>`: The input file.
-   `-o, --output <output_file>`: The output file.
-   `-p, --password <password>`: The password.
-   `-k, --keyfile <keyfile>`: The keyfile.
-   `--password-file <password_file>`: Read the password from a file.
-   `--random-name`: Use a random name for the output file.
-   `--add-padding`: Add random padding to the file (default).
-   `--no-padding`: Do not add random padding to the file.
-   `--hide-paths`: Hide file paths in the console output.
-   `--enable-compression`: Enable compression.
-   `--disable-compression`: Disable compression.

## Hardening Features

Thena_dev includes several advanced security features to protect against tampering and analysis:

-   **Runtime Integrity Checks**: The tool can monitor its own code at runtime to detect any modifications.
-   **Anti-Debugging**: The tool employs techniques to detect if it is being run under a debugger.
-   **Secure Memory Handling**: Sensitive data in memory (like encryption keys) is securely overwritten when no longer needed.
-   **Custom File Format**: The encrypted file format includes features like shuffled parts and an encrypted header to obscure its structure.

These features can be enabled or disabled in the `thena_config_v18.json` file.

## Logging

The tool generates a log file, `thena_encryptor.log`, which records information about its operations. The level of detail can be configured with the `log_level` setting in the configuration file.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
