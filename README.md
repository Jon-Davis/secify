# AESify

A command-line tool for encrypting and decrypting files using AES-256-GCM encryption with Argon2 key derivation.

## Features

- **Strong Encryption**: Uses AES-256-GCM for authenticated encryption
- **Secure Key Derivation**: Uses Argon2 to derive encryption keys from passwords
- **File Safety**: Prevents overwriting existing files during decryption
- **Interactive Mode**: User-friendly step-by-step dialog when no arguments provided
- **Command Line Interface**: Direct command-line usage for automation and scripts

## Installation

Make sure you have Rust installed, then clone and build the project:

```bash
git clone <repository-url>
cd aesify
cargo build --release
```

## Usage

### Interactive Mode

Simply run the program without any arguments to start the interactive mode:

```bash
aesify
```

This will guide you through the process step by step:
1. Choose whether to encrypt or decrypt
2. Enter the file path
3. Enter the password (with confirmation for encryption)

The interactive mode includes helpful validation:
- Checks if files exist before processing
- Ensures .aes extension for decryption
- Requires password confirmation for encryption
- Validates minimum password length (4 characters)

### Command Line Mode

### Encrypting a File

```bash
aesify encrypt --file <filename> --password <password>
```

This will create a new file with the `.aes` extension containing the encrypted data.

Example:
```bash
aesify encrypt --file document.txt --password "mySecurePassword123"
# Creates: document.txt.aes
```

### Decrypting a File

```bash
aesify decrypt --file <filename.aes> --password <password>
```

This will decrypt the `.aes` file and restore the original file.

Example:
```bash
aesify decrypt --file document.txt.aes --password "mySecurePassword123"
# Creates: document.txt
```

## Security Features

- **AES-256-GCM**: Provides both confidentiality and authenticity
- **Argon2**: Memory-hard key derivation function resistant to brute-force attacks
- **Random Salt**: Each encrypted file uses a unique random salt
- **Random Nonce**: Each encryption uses a unique random nonce
- **Password Verification**: Wrong passwords are detected and rejected

## File Format

The encrypted `.aes` files contain:
1. Salt (32 bytes) - Used for key derivation
2. Nonce (12 bytes) - Used for AES-GCM encryption
3. Ciphertext - The encrypted file data with authentication tag

## Security Considerations

- Use strong, unique passwords
- Keep your passwords secure and don't share them
- The program doesn't store passwords - you must remember them
- Losing the password means losing access to the encrypted data
- The encrypted files are only as secure as your password

## Building from Source

```bash
cargo build --release
```

The executable will be available at `target/release/aesify` (or `aesify.exe` on Windows).

## Dependencies

- `aes-gcm`: AES-GCM encryption
- `argon2`: Key derivation
- `clap`: Command-line argument parsing
- `rand`: Random number generation
- `anyhow`: Error handling
