# Thena_dev Encryption Tool

Thena_dev is a command-line encryption tool written in Python. It provides a secure way to encrypt and decrypt files using industry-standard cryptographic libraries.

## Features

- **Multiple Key Derivation Functions (KDFs):** Choose between Argon2id, scrypt, and PBKDF2 for key derivation.
- **Strong Encryption:** Uses AES-GCM for authenticated encryption.
- **Master Key Support:**  Create and use a master key for enhanced security.
- **Command-Line and Interactive Modes:**  Use the tool from the command line for scripting or in an interactive mode for ease of use.
- **Secure File Wiping:**  Securely delete original files after encryption or decryption.
- **Batch Processing:** Encrypt or decrypt multiple files in a directory at once.
- **Hardened Security:** Includes features like runtime integrity checks, anti-debugging, and secure memory handling.

## Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/thena-dev.git
    cd thena-dev
    ```

2.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Interactive Mode

To start the tool in interactive mode, simply run the script without any arguments:

```bash
python Thena_dev.py
```

You will be presented with a menu to choose between encrypting a file, decrypting a file, or exiting the program.

### Command-Line Mode

#### Simple Encryption

```bash
python Thena_dev.py --encrypt -i <input_file> -o <output_file> -p <password>
```

#### Simple Decryption

```bash
python Thena_dev.py --decrypt -i <input_file> -o <output_file> -p <password>
```

#### Encryption with a Master Key

```bash
python Thena_dev.py --encrypt -i <input_file> -o <output_file> -p <password> -k <keyfile>
```

#### Decryption with a Master Key

```bash
python Thena_dev.py --decrypt -i <input_file> -o <output_file> -p <password> -k <keyfile>
```

#### Batch Processing

To encrypt all files in a directory:

```bash
python Thena_dev.py --batch --encrypt --dir <directory> -p <password>
```

To decrypt all `.encrypted` files in a directory:

```bash
python Thena_dev.py --batch --decrypt --dir <directory> -p <password>
```

### Arguments

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
-   `--add-padding`: Add random padding to the file.
-   `--no-padding`: Do not add random padding to the file.
-   `--hide-paths`: Hide file paths in the output.
-   `--enable-compression`: Enable compression.
-   `--disable-compression`: Disable compression.
