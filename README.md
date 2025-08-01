# Secify

**Secify** is a secure file encryption program. It transforms any file or folder into an encrypted `.sec` container that can only be opened with the correct password.

## Key Features

- **Multiple Encryption Algorithms**: AES-256-GCM, ChaCha20-Poly1305, and XChaCha20-Poly1305
- **Directory Support**: Encrypts entire folders while preserving structure
- **Future-Proof**: Extensible CBOR header format for algorithm upgrades

## Installation

### From Source
```bash
git clone https://github.com/yourusername/secify
cd secify
cargo build --release
```

The binary will be available at `target/release/secify.exe` (Windows) or `target/release/secify` (Unix).

## Usage

Secify automatically detects whether to encrypt or decrypt based on the file extension:
- **Regular files/folders** → Encrypt to `.sec` format
- **`.sec` files** → Decrypt to original format

### Interactive Mode (Recommended)
```bash
secify
```

Follow the prompts to:
1. Select your file or directory
2. Choose encryption algorithm (for new encryptions)
3. Enter a secure password
4. Watch the progress as your data is protected

### Command Line Mode
```bash
# Encrypt a file with default algorithm (XChaCha20-Poly1305)
secify document.pdf

# Encrypt with specific algorithm
secify -a aes256 document.pdf

# Encrypt a directory
secify /path/to/folder

# Decrypt a .sec file
secify document.pdf.sec

# Provide password via command line (less secure)
secify -p mypassword document.pdf
```

### Algorithm Selection
- **XChaCha20-Poly1305** (default): 192-bit nonce prevents collisions
- **AES-256-GCM**: Hardware accelerated on most modern CPUs
- **ChaCha20-Poly1305**: Faster on mobile and older processors

### Key Derivation
- **Argon2id**: Winner of the Password Hashing Competition

## File Format: Securely Encrypted Container (.sec)

### Format Specification

The `.sec` format is a binary container with the following structure:

```
┌─────────────────────────────────────────────────────────────┐
│                    .sec File Format                         │
├─────────────────────────────────────────────────────────────┤
│ Header Length    │ 4 bytes (little-endian u32)              │
├─────────────────────────────────────────────────────────────┤
│ CBOR Header      │ Variable length (self-describing)        │
├─────────────────────────────────────────────────────────────┤
│ Encrypted Data   │ Variable length (algorithm-specific)     │
└─────────────────────────────────────────────────────────────┘
```

### CBOR Header Structure

The header contains all encryption metadata in CBOR format:

```rust
{
  "version": 1,                           // File format version
  "encryption_algorithm": "AES-256-GCM",  // Encryption method
  "kdf": {                                // Key derivation function
    "algorithm": "Argon2id",
    "version": "0x13",                    // Argon2 version 1.3
    "memory_cost": 131072,                // 128 MB in KB
    "time_cost": 8,                       // 8 iterations
    "parallelism": 4,                     // 4 threads
    "output_length": 32                   // 32-byte key
  },
  "compression": {
    "method": "ZIP-Stored",               // Compression algorithm
    "enabled": true                       // For directories only
  },
  "content_type": "File" | "Directory",   // Content type
  "salt": [32 bytes],                     // Random salt for key derivation
  "nonce": [12 bytes]                     // Random nonce for AES-GCM
}
```

## Examples

### Encrypting a Document
```bash
$ secify document.pdf
=== Secify Interactive Mode ===

Enter file or directory path: document.pdf
Detected non-.sec file - encrypting...
Enter password: [hidden input]
[████████████████████] 100% - Encryption complete
File encrypted successfully: document.pdf.sec
```

### Decrypting a Container
```bash
$ secify document.pdf.sec
=== Secify Interactive Mode ===

Enter file or directory path: document.pdf.sec
Detected .sec file - decrypting...
Enter password: [hidden input]
File format version: 1
Encryption: AES-256-GCM
Key derivation: Argon2id (128MB, 8 iterations, 4 threads)
Content type: File
[████████████████████] 100% - Decryption complete
File decrypted successfully: document.pdf
```

### Encrypting a Directory
```bash
$ secify /home/user/documents
=== Secify Interactive Mode ===

Enter file or directory path: /home/user/documents
Detected non-.sec file - encrypting...
Enter password: [hidden input]
Zipping directory...
[████████████████████] 100% - Encryption complete
Directory zipped and encrypted successfully: /home/user/documents.sec
```

## Error Handling

Secify provides clear error messages for common issues:

- **Wrong Password**: "Failed to decrypt data - incorrect password or corrupted file"
- **Corrupted File**: "Invalid encrypted file format"
- **Version Mismatch**: "Unsupported file format version"
- **Missing Files**: "Failed to read file: [filename]"


