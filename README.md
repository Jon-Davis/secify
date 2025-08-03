# Secify

**Secify** is a secure file encryption program. It transforms any file or folder into an encrypted `.sec` container that can only be opened with the correct password.

## Note
This is just a personal project, to explore different encryption methods.

## Key Features

- **Multiple Encryption Algorithms**: AES-256-GCM, ChaCha20-Poly1305, and XChaCha20-Poly1305
- **Optional Compression**: Zstandard (zstd) compression enabled by default (level 3) for smaller encrypted files
- **Directory Support**: Encrypts entire folders while preserving structure
- **Future-Proof**: Extensible Protocol Buffer header format for algorithm upgrades
- **Fully Streaming Architecture**: Process files of any size with constant memory usage
  - No temporary files or full-data buffering required
  - Enables encryption of arbitrarily large files and directories
  - Real-time processing: data flows directly from read → tar → compress → encrypt → write
  
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

### Streaming Architecture

Secify implements a fully streaming pipeline for optimal memory efficiency:

**Read → [Archive] → Compress → Encrypt → Write Pipeline:**
- **Single Files**: Content is read in chunks, optionally compressed, then encrypted and written directly (no TAR overhead)
- **Directories**: Files are recursively added to TAR stream, optionally compressed, encrypted on-the-fly, and written incrementally
- **Memory Usage**: Constant memory usage regardless of file/directory size (only chunk-size buffers)
- **Performance**: No temporary files, no full-data buffering, immediate processing of each chunk
- **Compression**: Optional zstd compression reduces file size at the cost of CPU time

This streaming approach enables encryption of arbitrarily large files and directories without memory constraints, while minimizing overhead for single files.

### Format Specification

The `.sec` format is a binary container with the following structure:

```
┌─────────────────────────────────────────────────────────────┐
│                    .sec File Format                         │
├─────────────────────────────────────────────────────────────┤
│ Header Length    │ 4 bytes (little-endian u32)              │
├─────────────────────────────────────────────────────────────┤
│ Protobuf Header  │ Variable length (self-describing)        │
├─────────────────────────────────────────────────────────────┤
│ Encrypted Data   │ Variable length (optionally compressed)  │
├─────────────────────────────────────────────────────────────┤
│ File HMAC        │ 32 bytes (HMAC-SHA256 of plaintext)      │
└─────────────────────────────────────────────────────────────┘
```

### Protocol Buffer Header Structure

The header contains all encryption metadata in Protocol Buffer format:

```rust
{
  "version": 1,                           // File format version
  "encryption_algorithm": "AES-256-GCM",  // Encryption method
  "compression": {                        // Optional compression configuration
    "algorithm": "zstd",                  // Compression algorithm (if used)
    "level": 3                           // Compression level (default: 3)
  },
  "kdf": {                                // Key derivation function
    "algorithm": "Argon2id",
    "version": "0x13",                    // Argon2 version 1.3
    "memory_cost": 131072,                // 128 MB in KB
    "time_cost": 8,                       // 8 iterations
    "parallelism": 4,                     // 4 threads
    "output_length": 32                   // 32-byte key
  },
  "salt": [32 bytes],                     // Random salt for key derivation
  "nonce": [8/16 bytes],                  // Base nonce for chunked encryption
  "chunk_size": 65536,                    // Chunk size in bytes (64KB default)
  "archive": "tar"                        // Optional: Archive format (only present for directories)
}
```

### Chunked Encryption Format

Data is encrypted in fixed-size chunks for efficient streaming and memory usage. 

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

### Encrypting a Folder
```bash
$ secify
=== Secify Interactive Mode ===

Enter the file or directory path (type 'ls' to list files): test_dir
Detected non-.sec file - will encrypt

Select encryption algorithm:
1. AES-256-GCM (hardware accelerated on most CPUs, 96-bit nonce)
2. ChaCha20-Poly1305 (faster on mobile/older CPUs, 96-bit nonce)
3. XChaCha20-Poly1305 (default, recommended for high-volume use, 192-bit nonce)
Enter choice (1, 2, or 3, default is 3):

Argon2id Key Derivation Settings:
Current: 128MB memory, 8 iterations, 4 threads
Customize Argon2 parameters? (y/N):

Compression Settings:
Select compression algorithm:
1. None (faster encryption, larger files)
2. Zstandard (zstd) (slower encryption, smaller files)
Enter choice (1 or 2, default is 1): 2
Compression level (1-22, default: 3, higher = better compression but slower): 3

Enter password for encryption: 

Confirm password:


Encrypting file...
Using TAR archive format with compression and full streaming pipeline (read→tar→compress→encrypt→write)
Streaming directory encryption with compression and full pipeline (TAR → Compress → Encrypt)...
Deriving encryption key with Argon2id (128MB, 8 iterations, 4 threads)...
Argon2 key derivation completed in 0.49 seconds
Counting files...
  Streaming TAR [00:00:00] [########################################] 4/4 Streaming directory encryption complete                                                                                                                  
Directory encrypted successfully: test_dir.sec
```

### Decrypting a Folder
```bash
$ secify
=== Secify Interactive Mode ===

Enter the file or directory path (type 'ls' to list files): test_dir.sec
Detected .sec file - will decrypt
Enter password for decryption:


Decrypting file...
TAR archive detected - using streaming decryption
File format version: 1
Encryption: XChaCha20-Poly1305
Compression: zstd (level 6)
Key derivation: Argon2id (128MB, 8 iterations, 4 threads)
Chunked encryption: 64KB chunks
Deriving encryption key with Argon2id (128MB, 8 iterations, 4 threads)...
Argon2 key derivation completed in 0.49 seconds
Decrypting data...
  Decrypting [00:00:00] [########################################] 4.52 KiB/4.52 KiB (12.17 MiB/s, 0s)                                                                                                                             
Verifying file integrity...
File integrity verified successfully
Decompressing data with zstd...
Extracting TAR directory...
Extracting TAR archive...
  Extracting TAR [00:00:00] [########################################] 4/4 TAR extraction complete!                                                                                                                                
Directory decrypted and extracted successfully: test_dir
```