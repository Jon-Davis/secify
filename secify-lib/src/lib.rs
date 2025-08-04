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
//! use secify_lib::{encrypt_core, decrypt_core, EncryptionAlgorithm, Argon2Params, Result, SecifyEvent, LogLevel};
//! use std::sync::Arc;
//! 
//! fn example() -> Result<()> {
//!     // Encrypt a file
//!     let params = Argon2Params::default();
//!     let event_callback = Arc::new(|event| {
//!         match event {
//!             SecifyEvent::EncryptProgress(progress) => println!("Encrypt progress: {:?}", progress),
//!             SecifyEvent::DecryptProgress(progress) => println!("Decrypt progress: {:?}", progress),
//!             SecifyEvent::Log { level, message } => {
//!                 match level {
//!                     LogLevel::Error => eprintln!("ERROR: {}", message),
//!                     LogLevel::Warning => println!("WARNING: {}", message),
//!                     LogLevel::Info => println!("INFO: {}", message),
//!                 }
//!             }
//!         }
//!     });
//!     
//!     encrypt_core(
//!         "input.txt",
//!         "output.sec", 
//!         "password",
//!         &EncryptionAlgorithm::XChaCha20Poly1305,
//!         &params,
//!         None, // No compression
//!         Some(event_callback.clone()),
//!     )?;
//!     
//!     // Decrypt a file
//!     decrypt_core(
//!         "output.sec",
//!         "restored.txt",
//!         "password", 
//!         Some(event_callback),
//!     )?;
//!     
//!     Ok(())
//! }
//! ```

pub mod crypto;
pub mod core;
pub mod error;
pub mod archive;
pub mod progress;
pub mod compression;
pub mod streaming;

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
};

pub use streaming::{
    StreamingEncryptionWriter, StreamingDecryptionReader,
};

pub use progress::{
    EncryptProgress, DecryptProgress, EncryptionInfo,
    ProgressAwareReader, SecifyEvent, LogLevel, EventCallback, no_op_callback
};

pub use archive::{
    SecArchiveWriter, SecArchiveReader, process_directory_sec
};

pub use compression::{
    CompressionBufferingWriter, create_decompression_reader
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
            None, // No event callback
        ).unwrap();
        
        assert!(encrypted_file.exists());
        
        // Test decryption
        decrypt_core(
            encrypted_file.to_str().unwrap(),
            decrypted_file.to_str().unwrap(),
            "test_password",
            None, // No event callback
        ).unwrap();
        
        assert!(decrypted_file.exists());
        let decrypted_content = fs::read(&decrypted_file).unwrap();
        assert_eq!(decrypted_content, b"Test content");
    }
}
