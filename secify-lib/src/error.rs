//! Error types for the secify library
//!
//! This module defines all the error types that can occur during encryption
//! and decryption operations, providing structured error handling.

use thiserror::Error;

/// The main error type for all secify library operations
#[derive(Error, Debug)]
pub enum SecifyError {
    /// IO operation failed
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic operation failed
    #[error("Cryptographic error: {message}")]
    Crypto { message: String },

    /// Key derivation failed
    #[error("Key derivation error: {message}")]
    KeyDerivation { message: String },

    /// Encryption operation failed
    #[error("Encryption error: {message}")]
    Encryption { message: String },

    /// Decryption operation failed
    #[error("Decryption error: {message}")]
    Decryption { message: String },

    /// Compression operation failed
    #[error("Compression error: {message}")]
    Compression { message: String },

    /// Decompression operation failed
    #[error("Decompression error: {message}")]
    Decompression { message: String },

    /// Archive operation failed (streaming archive format)
    #[error("Archive error: {message}")]
    Archive { message: String },

    /// Invalid configuration or parameters
    #[error("Invalid configuration: {message}")]
    InvalidConfig { message: String },

    /// Invalid file format or corrupted data
    #[error("Invalid file format: {message}")]
    InvalidFormat { message: String },

    /// Authentication/integrity check failed
    #[error("Authentication failed: {message}")]
    Authentication { message: String },

    /// File not found or path issues
    #[error("File error: {message}")]
    FileError { message: String },

    /// Serialization/deserialization failed
    #[error("Serialization error: {message}")]
    Serialization { message: String },

    /// Argon2 password hashing error
    #[error("Argon2 error: {0}")]
    Argon2(String),

    /// Generic error for cases not covered by specific error types
    #[error("Generic error: {message}")]
    Generic { message: String },
}

impl SecifyError {
    /// Create a crypto error with a custom message
    pub fn crypto<S: Into<String>>(message: S) -> Self {
        Self::Crypto {
            message: message.into(),
        }
    }

    /// Create a key derivation error with a custom message
    pub fn key_derivation<S: Into<String>>(message: S) -> Self {
        Self::KeyDerivation {
            message: message.into(),
        }
    }

    /// Create an encryption error with a custom message
    pub fn encryption<S: Into<String>>(message: S) -> Self {
        Self::Encryption {
            message: message.into(),
        }
    }

    /// Create a decryption error with a custom message
    pub fn decryption<S: Into<String>>(message: S) -> Self {
        Self::Decryption {
            message: message.into(),
        }
    }

    /// Create a compression error with a custom message
    pub fn compression<S: Into<String>>(message: S) -> Self {
        Self::Compression {
            message: message.into(),
        }
    }

    /// Create a decompression error with a custom message
    pub fn decompression<S: Into<String>>(message: S) -> Self {
        Self::Decompression {
            message: message.into(),
        }
    }

    /// Create an archive error with a custom message
    pub fn archive<S: Into<String>>(message: S) -> Self {
        Self::Archive {
            message: message.into(),
        }
    }

    /// Create an invalid config error with a custom message
    pub fn invalid_config<S: Into<String>>(message: S) -> Self {
        Self::InvalidConfig {
            message: message.into(),
        }
    }

    /// Create an invalid format error with a custom message
    pub fn invalid_format<S: Into<String>>(message: S) -> Self {
        Self::InvalidFormat {
            message: message.into(),
        }
    }

    /// Create an authentication error with a custom message
    pub fn authentication<S: Into<String>>(message: S) -> Self {
        Self::Authentication {
            message: message.into(),
        }
    }

    /// Create a file error with a custom message
    pub fn file_error<S: Into<String>>(message: S) -> Self {
        Self::FileError {
            message: message.into(),
        }
    }

    /// Create a generic error with a custom message
    pub fn generic<S: Into<String>>(message: S) -> Self {
        Self::Generic {
            message: message.into(),
        }
    }

    /// Create a serialization error with a custom message
    pub fn serialization<S: Into<String>>(message: S) -> Self {
        Self::Serialization {
            message: message.into(),
        }
    }
}

/// Manual From implementation for Argon2 errors since they don't implement std::error::Error
impl From<argon2::password_hash::Error> for SecifyError {
    fn from(err: argon2::password_hash::Error) -> Self {
        Self::Argon2(err.to_string())
    }
}

/// Result type alias for secify library operations
pub type Result<T> = std::result::Result<T, SecifyError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let crypto_err = SecifyError::crypto("test crypto error");
        assert!(matches!(crypto_err, SecifyError::Crypto { .. }));
        assert_eq!(crypto_err.to_string(), "Cryptographic error: test crypto error");

        let io_err = SecifyError::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(matches!(io_err, SecifyError::Io(_)));
    }

    #[test]
    fn test_error_display() {
        let err = SecifyError::encryption("Failed to encrypt data");
        let expected = "Encryption error: Failed to encrypt data";
        assert_eq!(err.to_string(), expected);
    }
}
