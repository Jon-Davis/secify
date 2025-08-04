//! Secify Core Library
//! 
//! A library for creating and reading encrypted .sec files with streaming encryption,
//! compression, and sec archive format support.
//! 
//! # Features
//! 
//! - **Multiple encryption algorithms**: AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305
//! - **Streaming encryption/decryption**: Memory-efficient processing of large files
//! - **Compression support**: zstd compression with configurable levels
//! - **Minimal archiving**: Efficient streaming format for both files and directories
//! - **Strong key derivation**: Argon2id with configurable parameters
//! - **File integrity**: HMAC-SHA256 verification for multi-chunk files
//! - **Progress reporting**: Callback-based progress tracking
//! 
//! # Examples
//! 
//! ```rust
//! use secify_lib::{encrypt_core, decrypt_core, EncryptionAlgorithm, Argon2Params, Result};
//! 
//! fn example() -> Result<()> {
//!     // Encrypt a file
//!     let params = Argon2Params::default();
//!     encrypt_core(
//!         "input.txt",
//!         "output.sec", 
//!         "password",
//!         &EncryptionAlgorithm::XChaCha20Poly1305,
//!         &params,
//!         None, // No compression
//!         &|progress| println!("Encrypt progress: {:?}", progress),
//!         &|msg| println!("Log: {}", msg),
//!     )?;
//!     
//!     // Decrypt a file
//!     decrypt_core(
//!         "output.sec",
//!         "restored.txt",
//!         "password", 
//!         &|progress| println!("Decrypt progress: {:?}", progress),
//!         &|msg| println!("Log: {}", msg),
//!     )?;
//!     
//!     Ok(())
//! }
//! ```

pub mod crypto;
pub mod core;
pub mod error;

// Re-export the main types and functions for convenience
pub use error::{SecifyError, Result};

pub use crypto::{
    EncryptionAlgorithm, CompressionAlgorithm, RuntimeCompressionConfig, Argon2Params, CompressionConfig,
    encrypt_data, decrypt_data, derive_key, derive_key_with_callback, generate_secure_random_bytes,
    generate_base_nonce, create_encryption_header, validate_header,
    deserialize_header_from_protobuf, serialize_header_to_protobuf, parse_algorithm,
    DEFAULT_CHUNK_SIZE, SALT_LENGTH, KEY_LENGTH, FILE_FORMAT_VERSION
};

pub use core::{
    encrypt_core, decrypt_core,
    EncryptProgress, DecryptProgress, EncryptionInfo,
    StreamingEncryptionWriter, StreamingDecryptionReader, CompressionBufferingWriter,
    EncryptProgressCallback, DecryptProgressCallback, LogCallback
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_library_public_api() {
        // Test that the main API is accessible
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test.txt");
        let encrypted_file = temp_dir.path().join("test.sec");
        let decrypted_file = temp_dir.path().join("test_restored.txt");
        
        fs::write(&input_file, b"Test content").unwrap();
        
        let algorithm = EncryptionAlgorithm::XChaCha20Poly1305;
        let params = Argon2Params::default();
        
        // Test encryption
        encrypt_core(
            input_file.to_str().unwrap(),
            encrypted_file.to_str().unwrap(),
            "test_password",
            &algorithm,
            &params,
            None,
            &|_| {}, // Progress callback
            &|_| {}, // Log callback
        ).unwrap();
        
        assert!(encrypted_file.exists());
        
        // Test decryption
        decrypt_core(
            encrypted_file.to_str().unwrap(),
            decrypted_file.to_str().unwrap(),
            "test_password",
            &|_| {}, // Progress callback
            &|_| {}, // Log callback
        ).unwrap();
        
        assert!(decrypted_file.exists());
        let decrypted_content = fs::read(&decrypted_file).unwrap();
        assert_eq!(decrypted_content, b"Test content");
    }
}
