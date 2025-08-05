# Secify

Secify is a secure file encryption tool. It encrypts files or directories into `.sec` containers that require a password.

**NOTE**: This is just a personal project to explore encryption technologies

## Features

- Encryption algorithms: AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305
- Optional compression (zstd)
- Directory support with custom archive format
- Streaming architecture: constant memory usage, no temp files
- Argon2id key derivation with recommended, constrained, and custom presets

## File Format: Securely Encrypted Container (.sec)

### Streaming Architecture

Streaming pipeline: Read → [Archive] → Compress → Encrypt → Write

- Single files: chunked, optionally compressed, encrypted directly
- Directories: archived to custom format, optionally compressed, encrypted
- Constant memory usage (chunk-size buffers only)
- No temporary files or full-data buffering
- Optional zstd compression

### Format Specification

The `.sec` format is a binary container with the following structure:

```
┌──────────────────────────────────────────────────────────────┐
│                    .sec File Format                          │
├──────────────────────────────────────────────────────────────┤
│ Public Header Len │ 2 bytes (little-endian u16)              │
├──────────────────────────────────────────────────────────────┤
│ Public Header     │ Variable length (encryption info only)   │
├──────────────────────────────────────────────────────────────┤
│ Private Header Len│ 2 bytes (little-endian u16)              │
├──────────────────────────────────────────────────────────────┤
│ Private Header    │ Variable length (encrypted metadata)     │
├──────────────────────────────────────────────────────────────┤
│ Encrypted Data    │ Variable length (optionally compressed)  │
├──────────────────────────────────────────────────────────────┤
│ File HMAC         │ 32 bytes (HMAC-SHA256, multi-chunk only) │
└──────────────────────────────────────────────────────────────┘
```

The format uses a split header design:
- Public Header: encryption parameters (unencrypted)
- Private Header: compression and archive metadata (encrypted)

Single-chunk files omit the HMAC section, relying on AEAD authentication.

### Protocol Buffer Header Structure

Public and private headers use Protocol Buffer format:

```rust
// Public Header (unencrypted)
{
  "version": 0,                            // File format version
  "encryption_algorithm": "AES-256-GCM",   // Encryption method
  "kdf_config": {                          // Key derivation configuration
    "standard_kdf": "ARGON2ID_RECOMMENDED" // Preset (2GB, 1 iter, 4 threads)
  },
  "salt": [32 bytes],                      // Random salt for key derivation
  "nonce": [8/16 bytes],                   // Base nonce for chunked encryption
  "chunk_size": 65536,                     // Chunk size in bytes (64KB default)
}

// Private Header (encrypted as part of data stream)
{
  "compression": {                        // Optional compression configuration
    "algorithm": "zstd"                   // Compression algorithm (if used)
  },
  "archive": "sec"                        // Optional: Archive format
}
```

### Chunked Encryption Format

Data is encrypted in fixed-size chunks: 

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

**Format Details:**
- Fixed-size chunks (except last): exactly `chunk_size` bytes
- Plaintext per chunk: `chunk_size - 16 bytes` (16 bytes for auth tag)
- Last chunk: ≤ `chunk_size` to fit remaining data
- Unique nonce per chunk: base nonce + chunk counter

### Sec Archive Format

Custom archive format for directories with minimal overhead.

#### Archive Structure

File entry format:

```
┌─────────────────────────────────────────────────────────────┐
│                    Sec Archive Entry                        │
├─────────────────────────────────────────────────────────────┤
│ Name Length      │ 2 bytes (little-endian u16)              │
├─────────────────────────────────────────────────────────────┤
│ File Name        │ Variable length (UTF-8 string)           │
├─────────────────────────────────────────────────────────────┤
│ File Size        │ 8 bytes (little-endian u64)              │
├─────────────────────────────────────────────────────────────┤
│ File Data        │ Variable length (raw file content)       │
└─────────────────────────────────────────────────────────────┘
```

**Archive Details:**
- Overhead: 10 bytes + filename length per file
- Sequential processing, no seeking required
- Relative paths preserved for directory reconstruction
- No block padding
- Archive ends when encrypted data stream ends

**Directory Handling:**
- Subdirectories flattened to relative paths
- Forward slash `/` path separators
- File metadata not preserved
- Empty directories recreated as needed

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

Multi-layer integrity protection:

**Per-Chunk Authentication (AEAD):**
- 16-byte authentication tag per chunk
- Detects chunk-level corruption or tampering
- Prevents chosen-ciphertext attacks
- Enables safe streaming decryption

**File-Level Integrity (HMAC):**
- 32-byte HMAC-SHA256 for multi-chunk files only
- Computed over original plaintext using encryption key
- Verified after successful decryption of all chunks
- Single-chunk files skip HMAC (AEAD sufficient)