# Secify

**Secify** is a secure file encryption program. It transforms any file or folder into an encrypted `.sec` container that can only be opened with the correct password.

## Note
This is just a personal project, to explore different encryption methods.

## Key Features

- **Multiple Encryption Algorithms**: AES-256-GCM, ChaCha20-Poly1305, and XChaCha20-Poly1305
- **Optional Compression**: Zstandard (zstd) compression enabled by default (level 3) for smaller encrypted files
- **Directory Support**: Encrypts entire folders while preserving structure
- **Fully Streaming Architecture**: Process files of any size with constant memory usage
  
### Algorithm Selection
- **XChaCha20-Poly1305** (default): 192-bit nonce prevents collisions
- **AES-256-GCM**: Hardware accelerated on most modern CPUs
- **ChaCha20-Poly1305**: Faster on mobile and older processors

### Argon2id Key Derivation
Secify uses Argon2id for key derivation with customizable parameters:

- **Memory Cost** (8-2048 MB, default: 128): Memory usage during key derivation
- **Time Cost** (1-100 iterations, default: 8): Number of iterations
- **Parallelism** (1-16 threads, default: 4): Number of parallel threads

## File Format: Securely Encrypted Container (.sec)

### Streaming Architecture

Secify implements a fully streaming pipeline for optimal memory efficiency:

**Read → [Archive] → Compress → Encrypt → Write Pipeline:**
- **Single Files**: Content is read in chunks, optionally compressed, then encrypted and written directly (no archive overhead)
- **Directories**: Files are recursively added to custom archive stream, optionally compressed, encrypted on-the-fly, and written incrementally
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
│ Public Header Len│ 2 bytes (little-endian u16)              │
├─────────────────────────────────────────────────────────────┤
│ Public Header    │ Variable length (encryption info only)   │
├─────────────────────────────────────────────────────────────┤
│ Private Header Len│ 2 bytes (little-endian u16)             │
├─────────────────────────────────────────────────────────────┤
│ Private Header   │ Variable length (encrypted metadata)     │
├─────────────────────────────────────────────────────────────┤
│ Encrypted Data   │ Variable length (optionally compressed)  │
├─────────────────────────────────────────────────────────────┤
│ File HMAC        │ 32 bytes (HMAC-SHA256, multi-chunk only) │
└─────────────────────────────────────────────────────────────┘
```

The format uses a **split header design** for enhanced security:
- **Public Header**: Contains only encryption parameters needed to start decryption
- **Private Header**: Contains compression and archive metadata, encrypted as part of the data stream

This ensures that metadata about the file structure is protected and cannot be analyzed without the password.

**Note:** Single-chunk files omit the HMAC section entirely, relying on AEAD authentication for integrity.

### Protocol Buffer Header Structure

The public header contains encryption metadata in Protocol Buffer format:

```rust
// Public Header (unencrypted)
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
  "salt": [32 bytes],                     // Random salt for key derivation
  "nonce": [8/16 bytes],                  // Base nonce for chunked encryption
  "chunk_size": 65536,                    // Chunk size in bytes (64KB default)
}

// Private Header (encrypted as part of data stream)
{
  "compression": {                        // Optional compression configuration
    "algorithm": "zstd"                   // Compression algorithm (if used)
  },
    "archive": "sec"                        // Optional: Archive format (only present for directories)
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

### Sec Archive Format

For directories, Secify uses a custom **sec archive format** that provides minimal overhead while preserving directory structure. This lightweight streaming format is specifically designed for efficient encryption and archival without the overhead of traditional archive formats like TAR.

#### Archive Structure

The sec archive format streams files sequentially with the following structure for each file entry:

```
┌─────────────────────────────────────────────────────────────┐
│                    Sec Archive Entry                        │
├─────────────────────────────────────────────────────────────┤
│ Name Length      │ 4 bytes (little-endian u32)              │
├─────────────────────────────────────────────────────────────┤
│ File Name        │ Variable length (UTF-8 string)           │
├─────────────────────────────────────────────────────────────┤
│ File Size        │ 8 bytes (little-endian u64)              │
├─────────────────────────────────────────────────────────────┤
│ File Data        │ Variable length (raw file content)       │
└─────────────────────────────────────────────────────────────┘
```

**Archive Benefits:**
- **Minimal Overhead**: Only 12 bytes per file + filename length 
- **Streaming-Friendly**: Files can be processed sequentially without seeking
- **Path Preservation**: Full relative paths maintained for directory reconstruction
- **No Padding**: Unlike TAR, no block-size padding waste (95% overhead reduction for small files)
- **Natural Termination**: Archive ends when encrypted data stream ends

**Directory Handling:**
- **Recursive Processing**: All subdirectories are flattened into relative paths
- **Path Separators**: Uses forward slashes `/` for cross-platform compatibility
- **Metadata**: File modification times and permissions are not preserved (encryption-focused)
- **Empty Directories**: Not explicitly stored (recreated during extraction as needed)

#### Example Directory Archive

For a directory structure like:
```
project/
├── src/
│   ├── main.rs
│   └── lib.rs
└── README.md
```

The sec archive would contain:
```
[12]["src/main.rs"][1024][...file data...]
[8]["src/lib.rs"][512][...file data...]
[9]["README.md"][256][...file data...]
```

### File Integrity Protection

The `.sec` format provides comprehensive integrity protection through multiple layers:

**Per-Chunk Authentication (AEAD):**
- Each chunk includes a 16-byte authentication tag
- Immediate detection of chunk-level corruption or tampering
- Prevents chosen-ciphertext attacks on individual chunks
- Enables safe streaming decryption

**File-Level Integrity (HMAC):**
- 32-byte HMAC-SHA256 appended to the end of multi-chunk files only
- Computed over the original plaintext data using the encryption key
- Verified after successful decryption of all chunks
- **Single-chunk files skip HMAC** - AEAD authentication provides sufficient integrity protection