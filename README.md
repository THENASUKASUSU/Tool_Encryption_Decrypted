# Thena Dev Encryption Tool

Thena Dev is a command-line encryption tool for securing files. It offers a range of features designed to provide a high level of security and flexibility.

## Features

- **Multiple Encryption Modes**: Encrypt and decrypt files using either a password or a master key.
- **Strong Encryption**: Utilizes AES-GCM for authenticated encryption.
- **Flexible Key Derivation**: Supports PBKDF2, Scrypt, and Argon2id for key derivation.
- **Secure File Wiping**: Securely deletes files by overwriting them with random data.
- **Batch Processing**: Encrypt or decrypt multiple files in a directory.
- **Command-Line and Interactive Modes**: Can be run with command-line arguments or in an interactive menu-driven mode.

## Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/thena-dev.git
   cd thena-dev
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Interactive Mode

To run the tool in interactive mode, simply execute the script without any arguments:

```bash
python Thena_dev.py
```

You will be presented with a menu to choose between encrypting a file, decrypting a file, or exiting the program.

### Command-Line Mode

#### Encryption

To encrypt a file, use the `--encrypt` flag with the input and output file paths and a password:

```bash
python Thena_dev.py --encrypt -i my_document.txt -o my_document.txt.encrypted -p "your-strong-password"
```

You can also use a keyfile for added security:

```bash
python Thena_dev.py --encrypt -i my_document.txt -o my_document.txt.encrypted -p "your-strong-password" -k /path/to/your/keyfile
```

#### Decryption

To decrypt a file, use the `--decrypt` flag:

```bash
python Thena_dev.py --decrypt -i my_document.txt.encrypted -o my_document.txt -p "your-strong-password"
```

### Batch Processing

To encrypt or decrypt all files in a directory, use the `--batch` flag with the `--dir` argument:

```bash
# Encrypt all files in the "documents" directory
python Thena_dev.py --batch --encrypt --dir documents -p "your-strong-password"

# Decrypt all files in the "encrypted_documents" directory
python Thena_dev.py --batch --decrypt --dir encrypted_documents -p "your-strong-password"
```
