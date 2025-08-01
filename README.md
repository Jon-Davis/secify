# Secify

**Secify** is a secure file encryption program. It transforms any file or folder into an encrypted `.sec` container that can only be opened with the correct password.

## Note
This is just a personal project, to explore different encryption methods.

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
# Encrypt a file with default settings (XChaCha20-Poly1305, 128MB memory, 8 iterations, 4 threads)
secify document.pdf

# Encrypt with specific algorithm
secify -a aes256 document.pdf

# Encrypt with custom Argon2 parameters for higher security
secify --memory-mb 256 --time-cost 12 --parallelism 8 document.pdf

# Encrypt with faster Argon2 parameters for performance
secify --memory-mb 64 --time-cost 4 --parallelism 2 document.pdf

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

### Argon2id Key Derivation
Secify uses Argon2id for key derivation with customizable parameters:

- **Memory Cost** (8-2048 MB, default: 128): Memory usage during key derivation
  - Higher = more secure against GPU attacks, but slower and uses more RAM
  - Recommended: 128MB for normal use, 256-512MB for high security

- **Time Cost** (1-100 iterations, default: 8): Number of iterations
  - Higher = more secure against brute force, but slower
  - Recommended: 8 for normal use, 12-16 for high security

- **Parallelism** (1-16 threads, default: 4): Number of parallel threads
  - Should match your CPU cores for best performance
  - Higher doesn't necessarily mean more secure

**Examples:**
- **Fast/Mobile**: `--memory-mb 32 --time-cost 4 --parallelism 2`
- **Balanced**: `--memory-mb 128 --time-cost 8 --parallelism 4` (default)
- **High Security**: `--memory-mb 512 --time-cost 16 --parallelism 8`

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
│ Encrypted Data   │ Variable length (data-specific)          │
├─────────────────────────────────────────────────────────────┤
│ File HMAC        │ 32 bytes (HMAC-SHA256 of plaintext)      │
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
  "nonce": [8/16 bytes],                  // Base nonce for chunked encryption
  "chunk_size": 65536                     // Chunk size in bytes (64KB default)
}
```

### Chunked Encryption Format

Data is encrypted in fixed-size chunks for efficient streaming and memory usage. The new format eliminates per-chunk length prefixes by using a consistent chunk size:

```
┌─────────────────────────────────────────────────────────────┐
│                    Encrypted Data                           │
├─────────────────────────────────────────────────────────────┤
│ Chunk 1 Data     │ Fixed size encrypted chunk (chunk_size)  │
├─────────────────────────────────────────────────────────────┤
│ Chunk 2 Data     │ Fixed size encrypted chunk (chunk_size)  │
├─────────────────────────────────────────────────────────────┤
│ Chunk 3 Data     │ Fixed size encrypted chunk (chunk_size)  │
├─────────────────────────────────────────────────────────────┤
│ ...              │ Additional fixed-size chunks             │
├─────────────────────────────────────────────────────────────┤
│ Last Chunk       │ Variable size (≤ chunk_size)             │
└─────────────────────────────────────────────────────────────┘
```

**Format Benefits:**
- **Fixed-Size Chunks**: Each encrypted chunk (except the last) is exactly `chunk_size` bytes
- **No Length Prefixes**: Eliminates 4-byte length headers, reducing overhead  
- **Streaming-Friendly**: No need to know total data length upfront - process chunks as they arrive
- **Natural Termination**: Decryption completes when ciphertext is exhausted

**Chunk Details:**
- **Plaintext per chunk**: `chunk_size - 16 bytes` (e.g., 64KB chunk = 65520 bytes plaintext + 16 byte auth tag)
- **Last chunk**: May be smaller than `chunk_size` to accommodate remaining data

Each chunk uses a unique nonce created by combining the base nonce with a chunk counter.

### File Integrity Protection

The `.sec` format provides comprehensive integrity protection through multiple layers:

**Per-Chunk Authentication (AEAD):**
- Each chunk includes a 16-byte authentication tag
- Immediate detection of chunk-level corruption or tampering
- Prevents chosen-ciphertext attacks on individual chunks
- Enables safe streaming decryption

**File-Level Integrity (HMAC):**
- 32-byte HMAC-SHA256 appended to the end of the file
- Computed over the original plaintext data using the encryption key
- Verified after successful decryption of all chunks

## Examples

### Encrypting a Document
```bash
$ secify document.pdf
=== Secify Interactive Mode ===

Enter file or directory path: document.pdf
Detected non-.sec file - encrypting...

Select encryption algorithm:
1. AES-256-GCM (hardware accelerated on most CPUs, 96-bit nonce)
2. ChaCha20-Poly1305 (faster on mobile/older CPUs, 96-bit nonce)
3. XChaCha20-Poly1305 (default, recommended for high-volume use, 192-bit nonce)
Enter choice (1, 2, or 3, default is 3): 

Argon2id Key Derivation Settings:
Current: 128MB memory, 8 iterations, 4 threads
Customize Argon2 parameters? (y/N): y
Memory cost in MB (8-2048, current: 128): 256
Time cost/iterations (1-100, current: 8): 12
Parallelism/threads (1-16, current: 4): 8
Final Argon2id settings: 256MB memory, 12 iterations, 8 threads

Enter password for encryption: [hidden input]
Confirm password: [hidden input]
[████████████████████] 100% - Encryption complete
File encrypted successfully: document.pdf.sec
```

### Command Line with Custom Argon2
```bash
$ secify --memory-mb 512 --time-cost 16 --parallelism 8 -a aes256 sensitive_data.pdf
Detected non-.sec file - encrypting...
Using encryption algorithm: AES-256-GCM
Using Argon2id parameters: 512MB memory, 16 iterations, 8 threads
Enter password for encryption: [hidden input]
Deriving encryption key with Argon2id (512MB, 16 iterations, 8 threads)...
Argon2 key derivation completed in 4.23 seconds
[████████████████████] 100% - Encryption complete
File encrypted successfully: sensitive_data.pdf.sec
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