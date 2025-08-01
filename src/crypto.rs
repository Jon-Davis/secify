use anyhow::{Result, Context, bail};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, Nonce as ChaNonce, XNonce};
use argon2::{Argon2, Algorithm, Version, Params, PasswordHasher};
use argon2::password_hash::{rand_core::RngCore, SaltString};
use serde::{Serialize, Deserialize};
use std::time::Instant;

// Constants
pub const SALT_LENGTH: usize = 32;
pub const KEY_LENGTH: usize = 32;
pub const FILE_FORMAT_VERSION: u32 = 1;
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10GB limit to prevent OOM

#[derive(Debug, Clone)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl EncryptionAlgorithm {
    pub fn from_string(s: &str) -> Result<Self> {
        match s {
            "AES-256-GCM" => Ok(EncryptionAlgorithm::Aes256Gcm),
            "ChaCha20-Poly1305" => Ok(EncryptionAlgorithm::ChaCha20Poly1305),
            "XChaCha20-Poly1305" => Ok(EncryptionAlgorithm::XChaCha20Poly1305),
            _ => bail!("Unsupported encryption algorithm: {}", s),
        }
    }
    
    pub fn to_string(&self) -> &'static str {
        match self {
            EncryptionAlgorithm::Aes256Gcm => "AES-256-GCM",
            EncryptionAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            EncryptionAlgorithm::XChaCha20Poly1305 => "XChaCha20-Poly1305",
        }
    }
    
    pub fn nonce_length(&self) -> usize {
        match self {
            EncryptionAlgorithm::Aes256Gcm => 12,  // AES-GCM uses 96-bit nonces
            EncryptionAlgorithm::ChaCha20Poly1305 => 12,  // ChaCha20-Poly1305 uses 96-bit nonces
            EncryptionAlgorithm::XChaCha20Poly1305 => 24,  // XChaCha20-Poly1305 uses 192-bit nonces
        }
    }
}

pub fn parse_algorithm(s: &str) -> Result<EncryptionAlgorithm, String> {
    match s.to_lowercase().as_str() {
        "aes256" | "aes" | "aes-256-gcm" => Ok(EncryptionAlgorithm::Aes256Gcm),
        "chacha20" | "chacha" | "chacha20-poly1305" => Ok(EncryptionAlgorithm::ChaCha20Poly1305),
        "xchacha20" | "xchacha" | "xchacha20-poly1305" => Ok(EncryptionAlgorithm::XChaCha20Poly1305),
        _ => Err(format!("Invalid algorithm '{}'. Valid options: aes256, chacha20, xchacha20", s)),
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptionHeader {
    /// File format version for future compatibility
    pub version: u32,
    /// Encryption algorithm identifier
    pub encryption_algorithm: String,
    /// Key derivation function details
    pub kdf: KeyDerivationConfig,
    /// Compression details
    pub compression: CompressionConfig,
    /// Content type (file or directory)
    pub content_type: ContentType,
    /// Salt for key derivation
    pub salt: Vec<u8>,
    /// Nonce/IV for encryption
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyDerivationConfig {
    /// Algorithm name (e.g., "Argon2id")
    pub algorithm: String,
    /// Version of the algorithm
    pub version: String,
    /// Memory cost in KB
    pub memory_cost: u32,
    /// Time cost (iterations)
    pub time_cost: u32,
    /// Parallelism (number of threads)
    pub parallelism: u32,
    /// Output length in bytes
    pub output_length: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CompressionConfig {
    /// Compression method used
    pub method: String,
    /// Whether compression was applied
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ContentType {
    File,
    Directory,
}

pub fn generate_secure_random_bytes(buffer: &mut [u8]) -> Result<()> {
    // Use cryptographically secure random number generator
    // OsRng provides entropy from the operating system's CSPRNG
    OsRng.fill_bytes(buffer);
    
    // Verify we got non-zero bytes (extremely unlikely but good practice)
    if buffer.iter().all(|&b| b == 0) {
        bail!("Failed to generate secure random bytes - all zeros returned");
    }
    
    Ok(())
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LENGTH]> {
    // Explicit Argon2id parameters for security and transparency
    let params = Params::new(
        131072, // memory cost: 128 MB
        8,     // time cost: 8 iterations
        4,     // parallelism: 4 threads
        Some(KEY_LENGTH) // output length: 32 bytes
    ).map_err(|e| anyhow::anyhow!("Failed to create Argon2 params: {}", e))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| anyhow::anyhow!("Failed to encode salt: {}", e))?;
    
    println!("Deriving encryption key with Argon2id (128MB, 8 iterations, 4 threads)...");
    let start_time = Instant::now();
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
    
    let duration = start_time.elapsed();
    println!("Argon2 key derivation completed in {:.2} seconds", duration.as_secs_f64());
    
    let hash = password_hash.hash
        .context("No hash in password hash")?;
    let hash_bytes = hash.as_bytes();
    
    if hash_bytes.len() < KEY_LENGTH {
        bail!("Hash too short for key derivation");
    }
    
    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&hash_bytes[..KEY_LENGTH]);
    Ok(key)
}

pub fn encrypt_data(algorithm: &EncryptionAlgorithm, key: &[u8; KEY_LENGTH], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("Failed to create AES cipher: {}", e))?;
            let nonce = Nonce::from_slice(nonce);
            cipher.encrypt(nonce, data)
                .map_err(|e| anyhow::anyhow!("Failed to encrypt with AES-256-GCM: {}", e))
        }
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("Failed to create ChaCha20 cipher: {}", e))?;
            let nonce = ChaNonce::from_slice(nonce);
            cipher.encrypt(nonce, data)
                .map_err(|e| anyhow::anyhow!("Failed to encrypt with ChaCha20-Poly1305: {}", e))
        }
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("Failed to create XChaCha20 cipher: {}", e))?;
            let nonce = XNonce::from_slice(nonce);
            cipher.encrypt(nonce, data)
                .map_err(|e| anyhow::anyhow!("Failed to encrypt with XChaCha20-Poly1305: {}", e))
        }
    }
}

pub fn decrypt_data(algorithm: &EncryptionAlgorithm, key: &[u8; KEY_LENGTH], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("Failed to create AES cipher: {}", e))?;
            let nonce = Nonce::from_slice(nonce);
            cipher.decrypt(nonce, ciphertext)
                .map_err(|e| anyhow::anyhow!("Failed to decrypt with AES-256-GCM - incorrect password or corrupted file: {}", e))
        }
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("Failed to create ChaCha20 cipher: {}", e))?;
            let nonce = ChaNonce::from_slice(nonce);
            cipher.decrypt(nonce, ciphertext)
                .map_err(|e| anyhow::anyhow!("Failed to decrypt with ChaCha20-Poly1305 - incorrect password or corrupted file: {}", e))
        }
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| anyhow::anyhow!("Failed to create XChaCha20 cipher: {}", e))?;
            let nonce = XNonce::from_slice(nonce);
            cipher.decrypt(nonce, ciphertext)
                .map_err(|e| anyhow::anyhow!("Failed to decrypt with XChaCha20-Poly1305 - incorrect password or corrupted file: {}", e))
        }
    }
}

pub fn create_encryption_header(salt: &[u8], nonce: &[u8], is_directory: bool, algorithm: &EncryptionAlgorithm) -> EncryptionHeader {
    EncryptionHeader {
        version: FILE_FORMAT_VERSION,
        encryption_algorithm: algorithm.to_string().to_owned(),
        kdf: KeyDerivationConfig {
            algorithm: "Argon2id".to_owned(),
            version: "0x13".to_owned(),
            memory_cost: 131072, // 128 MB in KB
            time_cost: 8,
            parallelism: 4,
            output_length: KEY_LENGTH as u32,
        },
        compression: CompressionConfig {
            method: "ZIP-Stored".to_owned(),
            enabled: is_directory,
        },
        content_type: if is_directory { ContentType::Directory } else { ContentType::File },
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
    }
}

pub fn serialize_header_to_cbor(header: &EncryptionHeader) -> Result<Vec<u8>> {
    let mut cbor_data = Vec::new();
    ciborium::ser::into_writer(header, &mut cbor_data)
        .context("Failed to serialize header to CBOR")?;
    Ok(cbor_data)
}

pub fn deserialize_header_from_cbor(cbor_data: &[u8]) -> Result<EncryptionHeader> {
    let header: EncryptionHeader = ciborium::de::from_reader(cbor_data)
        .context("Failed to deserialize header from CBOR")?;
    Ok(header)
}

pub fn validate_header(header: &EncryptionHeader) -> Result<()> {
    // Check version compatibility
    if header.version > FILE_FORMAT_VERSION {
        bail!("Unsupported file format version: {}. This tool supports up to version {}.", 
              header.version, FILE_FORMAT_VERSION);
    }
    
    // Validate encryption algorithm (parse to ensure it's supported)
    let algorithm = EncryptionAlgorithm::from_string(&header.encryption_algorithm)?;
    
    // Validate KDF
    if header.kdf.algorithm != "Argon2id" {
        bail!("Unsupported key derivation function: {}", header.kdf.algorithm);
    }
    
    // Validate salt and nonce lengths
    if header.salt.len() != SALT_LENGTH {
        bail!("Invalid salt length: expected {}, got {}", SALT_LENGTH, header.salt.len());
    }
    
    let expected_nonce_length = algorithm.nonce_length();
    if header.nonce.len() != expected_nonce_length {
        bail!("Invalid nonce length for {}: expected {}, got {}", 
              algorithm.to_string(), expected_nonce_length, header.nonce.len());
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test data constants
    const TEST_PASSWORD: &str = "TestPassword123!";
    const TEST_DATA: &[u8] = b"Hello, World! This is test data for encryption.";
    
    fn create_test_salt() -> [u8; SALT_LENGTH] {
        [1u8; SALT_LENGTH] // Fixed salt for reproducible tests
    }
    
    fn create_test_nonce(algorithm: &EncryptionAlgorithm) -> Vec<u8> {
        vec![2u8; algorithm.nonce_length()] // Fixed nonce for reproducible tests
    }

    #[test]
    fn test_encryption_algorithm_from_string() {
        assert!(matches!(
            EncryptionAlgorithm::from_string("AES-256-GCM").unwrap(),
            EncryptionAlgorithm::Aes256Gcm
        ));
        assert!(matches!(
            EncryptionAlgorithm::from_string("ChaCha20-Poly1305").unwrap(),
            EncryptionAlgorithm::ChaCha20Poly1305
        ));
        assert!(matches!(
            EncryptionAlgorithm::from_string("XChaCha20-Poly1305").unwrap(),
            EncryptionAlgorithm::XChaCha20Poly1305
        ));
        
        // Test invalid algorithm
        assert!(EncryptionAlgorithm::from_string("Invalid-Algorithm").is_err());
    }

    #[test]
    fn test_encryption_algorithm_to_string() {
        assert_eq!(EncryptionAlgorithm::Aes256Gcm.to_string(), "AES-256-GCM");
        assert_eq!(EncryptionAlgorithm::ChaCha20Poly1305.to_string(), "ChaCha20-Poly1305");
        assert_eq!(EncryptionAlgorithm::XChaCha20Poly1305.to_string(), "XChaCha20-Poly1305");
    }

    #[test]
    fn test_encryption_algorithm_nonce_length() {
        assert_eq!(EncryptionAlgorithm::Aes256Gcm.nonce_length(), 12);
        assert_eq!(EncryptionAlgorithm::ChaCha20Poly1305.nonce_length(), 12);
        assert_eq!(EncryptionAlgorithm::XChaCha20Poly1305.nonce_length(), 24);
    }

    #[test]
    fn test_parse_algorithm() {
        // Test valid algorithms
        assert!(matches!(parse_algorithm("aes256").unwrap(), EncryptionAlgorithm::Aes256Gcm));
        assert!(matches!(parse_algorithm("AES").unwrap(), EncryptionAlgorithm::Aes256Gcm));
        assert!(matches!(parse_algorithm("aes-256-gcm").unwrap(), EncryptionAlgorithm::Aes256Gcm));
        
        assert!(matches!(parse_algorithm("chacha20").unwrap(), EncryptionAlgorithm::ChaCha20Poly1305));
        assert!(matches!(parse_algorithm("CHACHA").unwrap(), EncryptionAlgorithm::ChaCha20Poly1305));
        assert!(matches!(parse_algorithm("chacha20-poly1305").unwrap(), EncryptionAlgorithm::ChaCha20Poly1305));
        
        assert!(matches!(parse_algorithm("xchacha20").unwrap(), EncryptionAlgorithm::XChaCha20Poly1305));
        assert!(matches!(parse_algorithm("XCHACHA").unwrap(), EncryptionAlgorithm::XChaCha20Poly1305));
        assert!(matches!(parse_algorithm("xchacha20-poly1305").unwrap(), EncryptionAlgorithm::XChaCha20Poly1305));
        
        // Test invalid algorithm
        assert!(parse_algorithm("invalid").is_err());
    }

    #[test]
    fn test_generate_secure_random_bytes() {
        let mut buffer1 = [0u8; 32];
        let mut buffer2 = [0u8; 32];
        
        // Generate random bytes
        generate_secure_random_bytes(&mut buffer1).unwrap();
        generate_secure_random_bytes(&mut buffer2).unwrap();
        
        // Buffers should not be all zeros
        assert_ne!(buffer1, [0u8; 32]);
        assert_ne!(buffer2, [0u8; 32]);
        
        // Buffers should be different (extremely unlikely to be the same)
        assert_ne!(buffer1, buffer2);
    }

    #[test]
    fn test_derive_key_consistency() {
        let salt = create_test_salt();
        
        // Same password and salt should produce same key
        let key1 = derive_key(TEST_PASSWORD, &salt).unwrap();
        let key2 = derive_key(TEST_PASSWORD, &salt).unwrap();
        assert_eq!(key1, key2);
        
        // Different password should produce different key
        let key3 = derive_key("DifferentPassword", &salt).unwrap();
        assert_ne!(key1, key3);
        
        // Different salt should produce different key
        let different_salt = [2u8; SALT_LENGTH];
        let key4 = derive_key(TEST_PASSWORD, &different_salt).unwrap();
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_encrypt_decrypt_aes256gcm() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let key = derive_key(TEST_PASSWORD, &salt).unwrap();
        
        // Encrypt data
        let ciphertext = encrypt_data(&algorithm, &key, &nonce, TEST_DATA).unwrap();
        assert_ne!(ciphertext, TEST_DATA);
        assert!(ciphertext.len() > TEST_DATA.len()); // Should be larger due to authentication tag
        
        // Decrypt data
        let plaintext = decrypt_data(&algorithm, &key, &nonce, &ciphertext).unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }

    #[test]
    fn test_encrypt_decrypt_chacha20poly1305() {
        let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let key = derive_key(TEST_PASSWORD, &salt).unwrap();
        
        // Encrypt data
        let ciphertext = encrypt_data(&algorithm, &key, &nonce, TEST_DATA).unwrap();
        assert_ne!(ciphertext, TEST_DATA);
        assert!(ciphertext.len() > TEST_DATA.len()); // Should be larger due to authentication tag
        
        // Decrypt data
        let plaintext = decrypt_data(&algorithm, &key, &nonce, &ciphertext).unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }

    #[test]
    fn test_encrypt_decrypt_xchacha20poly1305() {
        let algorithm = EncryptionAlgorithm::XChaCha20Poly1305;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let key = derive_key(TEST_PASSWORD, &salt).unwrap();
        
        // Encrypt data
        let ciphertext = encrypt_data(&algorithm, &key, &nonce, TEST_DATA).unwrap();
        assert_ne!(ciphertext, TEST_DATA);
        assert!(ciphertext.len() > TEST_DATA.len()); // Should be larger due to authentication tag
        
        // Decrypt data
        let plaintext = decrypt_data(&algorithm, &key, &nonce, &ciphertext).unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let key = derive_key(TEST_PASSWORD, &salt).unwrap();
        
        // Encrypt with correct key
        let ciphertext = encrypt_data(&algorithm, &key, &nonce, TEST_DATA).unwrap();
        
        // Try to decrypt with wrong key
        let wrong_key = derive_key("WrongPassword", &salt).unwrap();
        let result = decrypt_data(&algorithm, &wrong_key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_nonce_fails() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let key = derive_key(TEST_PASSWORD, &salt).unwrap();
        
        // Encrypt with correct nonce
        let ciphertext = encrypt_data(&algorithm, &key, &nonce, TEST_DATA).unwrap();
        
        // Try to decrypt with wrong nonce
        let wrong_nonce = vec![3u8; algorithm.nonce_length()];
        let result = decrypt_data(&algorithm, &key, &wrong_nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_encryption_header() {
        let algorithm = EncryptionAlgorithm::XChaCha20Poly1305;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        
        // Test file header
        let header = create_encryption_header(&salt, &nonce, false, &algorithm);
        assert_eq!(header.version, FILE_FORMAT_VERSION);
        assert_eq!(header.encryption_algorithm, "XChaCha20-Poly1305");
        assert_eq!(header.kdf.algorithm, "Argon2id");
        assert_eq!(header.kdf.memory_cost, 131072);
        assert_eq!(header.kdf.time_cost, 8);
        assert_eq!(header.kdf.parallelism, 4);
        assert_eq!(header.compression.enabled, false);
        assert!(matches!(header.content_type, ContentType::File));
        assert_eq!(header.salt, salt.to_vec());
        assert_eq!(header.nonce, nonce);
        
        // Test directory header
        let dir_header = create_encryption_header(&salt, &nonce, true, &algorithm);
        assert_eq!(dir_header.compression.enabled, true);
        assert!(matches!(dir_header.content_type, ContentType::Directory));
    }

    #[test]
    fn test_serialize_deserialize_header_cbor() {
        let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let original_header = create_encryption_header(&salt, &nonce, true, &algorithm);
        
        // Serialize to CBOR
        let cbor_data = serialize_header_to_cbor(&original_header).unwrap();
        assert!(!cbor_data.is_empty());
        
        // Deserialize from CBOR
        let deserialized_header = deserialize_header_from_cbor(&cbor_data).unwrap();
        
        // Compare fields
        assert_eq!(original_header.version, deserialized_header.version);
        assert_eq!(original_header.encryption_algorithm, deserialized_header.encryption_algorithm);
        assert_eq!(original_header.kdf.algorithm, deserialized_header.kdf.algorithm);
        assert_eq!(original_header.kdf.memory_cost, deserialized_header.kdf.memory_cost);
        assert_eq!(original_header.salt, deserialized_header.salt);
        assert_eq!(original_header.nonce, deserialized_header.nonce);
    }

    #[test]
    fn test_validate_header_success() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let header = create_encryption_header(&salt, &nonce, false, &algorithm);
        
        // Valid header should pass validation
        assert!(validate_header(&header).is_ok());
    }

    #[test]
    fn test_validate_header_invalid_version() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let mut header = create_encryption_header(&salt, &nonce, false, &algorithm);
        
        // Set invalid version
        header.version = FILE_FORMAT_VERSION + 1;
        assert!(validate_header(&header).is_err());
    }

    #[test]
    fn test_validate_header_invalid_algorithm() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let mut header = create_encryption_header(&salt, &nonce, false, &algorithm);
        
        // Set invalid algorithm
        header.encryption_algorithm = "Invalid-Algorithm".to_string();
        assert!(validate_header(&header).is_err());
    }

    #[test]
    fn test_validate_header_invalid_kdf() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let mut header = create_encryption_header(&salt, &nonce, false, &algorithm);
        
        // Set invalid KDF
        header.kdf.algorithm = "PBKDF2".to_string();
        assert!(validate_header(&header).is_err());
    }

    #[test]
    fn test_validate_header_invalid_salt_length() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let mut header = create_encryption_header(&salt, &nonce, false, &algorithm);
        
        // Set invalid salt length
        header.salt = vec![1u8; 16]; // Wrong length
        assert!(validate_header(&header).is_err());
    }

    #[test]
    fn test_validate_header_invalid_nonce_length() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let mut header = create_encryption_header(&salt, &nonce, false, &algorithm);
        
        // Set invalid nonce length
        header.nonce = vec![2u8; 8]; // Wrong length for AES-GCM
        assert!(validate_header(&header).is_err());
    }

    #[test]
    fn test_encryption_algorithms_are_not_interchangeable() {
        let salt = create_test_salt();
        let key = derive_key(TEST_PASSWORD, &salt).unwrap();
        
        // Encrypt with AES-256-GCM
        let aes_algorithm = EncryptionAlgorithm::Aes256Gcm;
        let aes_nonce = create_test_nonce(&aes_algorithm);
        let aes_ciphertext = encrypt_data(&aes_algorithm, &key, &aes_nonce, TEST_DATA).unwrap();
        
        // Try to decrypt with ChaCha20-Poly1305 (should fail)
        let chacha_algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
        let chacha_nonce = create_test_nonce(&chacha_algorithm);
        let result = decrypt_data(&chacha_algorithm, &key, &chacha_nonce, &aes_ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_data_encryption() {
        let algorithm = EncryptionAlgorithm::XChaCha20Poly1305;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let key = derive_key(TEST_PASSWORD, &salt).unwrap();
        
        let empty_data = b"";
        
        // Encrypt empty data
        let ciphertext = encrypt_data(&algorithm, &key, &nonce, empty_data).unwrap();
        assert!(!ciphertext.is_empty()); // Should still have authentication tag
        
        // Decrypt empty data
        let plaintext = decrypt_data(&algorithm, &key, &nonce, &ciphertext).unwrap();
        assert_eq!(plaintext, empty_data);
    }

    #[test]
    fn test_large_data_encryption() {
        let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let key = derive_key(TEST_PASSWORD, &salt).unwrap();
        
        // Create 1MB of test data
        let large_data = vec![0x42u8; 1024 * 1024];
        
        // Encrypt large data
        let ciphertext = encrypt_data(&algorithm, &key, &nonce, &large_data).unwrap();
        assert_ne!(ciphertext.len(), large_data.len());
        
        // Decrypt large data
        let plaintext = decrypt_data(&algorithm, &key, &nonce, &ciphertext).unwrap();
        assert_eq!(plaintext, large_data);
    }
}
