use crate::error::{SecifyError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, Nonce as ChaNonce, XNonce};
use argon2::{Argon2, Algorithm, Version, Params, PasswordHasher};
use argon2::password_hash::{rand_core::RngCore, SaltString};
use std::time::Instant;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use prost::Message;

// Constants
pub const SALT_LENGTH: usize = 32;
pub const KEY_LENGTH: usize = 32;
pub const FILE_FORMAT_VERSION: u32 = 0;
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10GB limit to prevent OOM
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks for streaming encryption

// Default Argon2 parameters
pub const DEFAULT_MEMORY_MB: u32 = 128;
pub const DEFAULT_TIME_COST: u32 = 8;
pub const DEFAULT_PARALLELISM: u32 = 4;

#[derive(Debug, Clone)]
pub struct Argon2Params {
    pub memory_mb: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_mb: DEFAULT_MEMORY_MB,
            time_cost: DEFAULT_TIME_COST,
            parallelism: DEFAULT_PARALLELISM,
        }
    }
}

impl Argon2Params {
    pub fn new(memory_mb: u32, time_cost: u32, parallelism: u32) -> Result<Self> {
        // Validate parameters
        if memory_mb < 8 {
            return Err(SecifyError::invalid_config("Memory cost must be at least 8 MB"));
        }
        if memory_mb > 2048 {
            return Err(SecifyError::invalid_config("Memory cost cannot exceed 2048 MB (2GB)"));
        }
        if time_cost < 1 {
            return Err(SecifyError::invalid_config("Time cost must be at least 1 iteration"));
        }
        if time_cost > 100 {
            return Err(SecifyError::invalid_config("Time cost cannot exceed 100 iterations"));
        }
        if parallelism < 1 {
            return Err(SecifyError::invalid_config("Parallelism must be at least 1 thread"));
        }
        if parallelism > 16 {
            return Err(SecifyError::invalid_config("Parallelism cannot exceed 16 threads"));
        }
        
        Ok(Self {
            memory_mb,
            time_cost,
            parallelism,
        })
    }
    
    pub fn memory_kb(&self) -> u32 {
        self.memory_mb * 1024
    }
}

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
            _ => Err(SecifyError::invalid_config(format!("Unsupported encryption algorithm: {}", s))),
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
    
    pub fn auth_tag_size(&self) -> usize {
        match self {
            EncryptionAlgorithm::Aes256Gcm => 16,          // AES-GCM uses 128-bit auth tags
            EncryptionAlgorithm::ChaCha20Poly1305 => 16,   // ChaCha20-Poly1305 uses 128-bit auth tags
            EncryptionAlgorithm::XChaCha20Poly1305 => 16,  // XChaCha20-Poly1305 uses 128-bit auth tags
        }
    }
}

pub fn parse_algorithm(s: &str) -> Result<EncryptionAlgorithm> {
    match s.to_lowercase().as_str() {
        "aes256" | "aes" | "aes-256-gcm" => Ok(EncryptionAlgorithm::Aes256Gcm),
        "chacha20" | "chacha" | "chacha20-poly1305" => Ok(EncryptionAlgorithm::ChaCha20Poly1305),
        "xchacha20" | "xchacha" | "xchacha20-poly1305" => Ok(EncryptionAlgorithm::XChaCha20Poly1305),
        _ => Err(SecifyError::invalid_config(format!("Invalid algorithm '{s}'. Valid options: aes256, chacha20, xchacha20"))),
    }
}

#[derive(Debug, Clone)]
pub enum CompressionAlgorithm {
    None,
    Zstd,
}

impl CompressionAlgorithm {
    pub fn from_string(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "none" => Ok(CompressionAlgorithm::None),
            "zstd" => Ok(CompressionAlgorithm::Zstd),
            _ => Err(SecifyError::invalid_config(format!("Unsupported compression algorithm: {}", s))),
        }
    }
    
    pub fn to_string(&self) -> &'static str {
        match self {
            CompressionAlgorithm::None => "none",
            CompressionAlgorithm::Zstd => "zstd",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeCompressionConfig {
    pub algorithm: String,
    pub level: i32,
}

// Include the generated protobuf structs
include!(concat!(env!("OUT_DIR"), "/secify.rs"));

pub fn generate_secure_random_bytes(buffer: &mut [u8]) -> Result<()> {
    // Use cryptographically secure random number generator
    // OsRng provides entropy from the operating system's CSPRNG
    OsRng.fill_bytes(buffer);
    
    // Verify we got non-zero bytes (extremely unlikely but good practice)
    if buffer.iter().all(|&b| b == 0) {
        return Err(SecifyError::crypto("Failed to generate secure random bytes - all zeros returned"));
    }
    
    Ok(())
}

pub fn derive_key(password: &str, salt: &[u8], argon2_params: &Argon2Params) -> Result<[u8; KEY_LENGTH]> {
    derive_key_with_callback(password, salt, argon2_params, &|_| {})
}

pub fn derive_key_with_callback(password: &str, salt: &[u8], argon2_params: &Argon2Params, log_callback: &dyn Fn(&str)) -> Result<[u8; KEY_LENGTH]> {
    // Explicit Argon2id parameters for security and transparency
    let params = Params::new(
        argon2_params.memory_kb(), // memory cost in KB
        argon2_params.time_cost,   // time cost: iterations
        argon2_params.parallelism, // parallelism: threads
        Some(KEY_LENGTH) // output length: 32 bytes
    ).map_err(|e| SecifyError::key_derivation(format!("Failed to create Argon2 params: {}", e)))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| SecifyError::key_derivation(format!("Failed to encode salt: {}", e)))?;
    
    log_callback(&format!("Deriving encryption key with Argon2id ({}MB, {} iterations, {} threads)...", 
             argon2_params.memory_mb, argon2_params.time_cost, argon2_params.parallelism));
    let start_time = Instant::now();
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| SecifyError::key_derivation(format!("Failed to hash password: {}", e)))?;
    
    let duration = start_time.elapsed();
    log_callback(&format!("Argon2 key derivation completed in {:.2} seconds", duration.as_secs_f64()));
    
    let hash = password_hash.hash
        .ok_or_else(|| SecifyError::key_derivation("No hash in password hash"))?;
    let hash_bytes = hash.as_bytes();
    
    if hash_bytes.len() < KEY_LENGTH {
        return Err(SecifyError::key_derivation("Hash too short for key derivation"));
    }
    
    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&hash_bytes[..KEY_LENGTH]);
    Ok(key)
}

pub fn encrypt_data(algorithm: &EncryptionAlgorithm, key: &[u8; KEY_LENGTH], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| SecifyError::encryption(format!("Failed to create AES cipher: {}", e)))?;
            let nonce = Nonce::from_slice(nonce);
            cipher.encrypt(nonce, data)
                .map_err(|e| SecifyError::encryption(format!("Failed to encrypt with AES-256-GCM: {}", e)))
        }
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| SecifyError::encryption(format!("Failed to create ChaCha20 cipher: {}", e)))?;
            let nonce = ChaNonce::from_slice(nonce);
            cipher.encrypt(nonce, data)
                .map_err(|e| SecifyError::encryption(format!("Failed to encrypt with ChaCha20-Poly1305: {}", e)))
        }
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| SecifyError::encryption(format!("Failed to create XChaCha20 cipher: {}", e)))?;
            let nonce = XNonce::from_slice(nonce);
            cipher.encrypt(nonce, data)
                .map_err(|e| SecifyError::encryption(format!("Failed to encrypt with XChaCha20-Poly1305: {}", e)))
        }
    }
}

/// Encrypt data in chunks for streaming encryption with fixed chunk sizes
pub fn encrypt_data_chunked(algorithm: &EncryptionAlgorithm, key: &[u8; KEY_LENGTH], base_nonce: &[u8], data: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
    if chunk_size == 0 {
        return Err(SecifyError::invalid_config("Chunk size cannot be zero"));
    }
    
    let auth_tag_size = algorithm.auth_tag_size();
    if chunk_size <= auth_tag_size {
        return Err(SecifyError::invalid_config(format!("Chunk size must be larger than authentication tag size ({} bytes)", auth_tag_size)));
    }
    
    // Calculate plaintext size per chunk to ensure fixed encrypted chunk size
    let plaintext_chunk_size = chunk_size - auth_tag_size;
    
    let mut result = Vec::new();
    let mut chunk_counter: u64 = 0;
    
    for chunk in data.chunks(plaintext_chunk_size) {
        let chunk_nonce = create_chunk_nonce(algorithm, base_nonce, chunk_counter)?;
        let encrypted_chunk = encrypt_data(algorithm, key, &chunk_nonce, chunk)?;
        
        // Verify the encrypted chunk size is as expected (except for the last chunk)
        let expected_size = chunk.len() + auth_tag_size;
        if encrypted_chunk.len() != expected_size {
            return Err(SecifyError::encryption(format!("Unexpected encrypted chunk size: got {}, expected {}", encrypted_chunk.len(), expected_size)));
        }
        
        // Store encrypted chunk directly without length prefix
        result.extend_from_slice(&encrypted_chunk);
        
        chunk_counter += 1;
    }
    
    Ok(result)
}

/// Create a unique nonce for each chunk by combining base nonce with chunk counter
fn create_chunk_nonce(algorithm: &EncryptionAlgorithm, base_nonce: &[u8], chunk_counter: u64) -> Result<Vec<u8>> {
    let nonce_length = algorithm.nonce_length();
    let mut chunk_nonce = vec![0u8; nonce_length];
    
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm | EncryptionAlgorithm::ChaCha20Poly1305 => {
            // 96-bit nonces: 8 bytes base + 4 bytes counter
            if base_nonce.len() != 8 {
                return Err(SecifyError::invalid_config(format!("Base nonce for {}/ChaCha20 must be 8 bytes, got {}", algorithm.to_string(), base_nonce.len())));
            }
            chunk_nonce[..8].copy_from_slice(base_nonce);
            chunk_nonce[8..12].copy_from_slice(&(chunk_counter as u32).to_le_bytes());
        }
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            // 192-bit nonces: 16 bytes base + 8 bytes counter
            if base_nonce.len() != 16 {
                return Err(SecifyError::invalid_config(format!("Base nonce for XChaCha20 must be 16 bytes, got {}", base_nonce.len())));
            }
            chunk_nonce[..16].copy_from_slice(base_nonce);
            chunk_nonce[16..24].copy_from_slice(&chunk_counter.to_le_bytes());
        }
    }
    
    Ok(chunk_nonce)
}

pub fn decrypt_data(algorithm: &EncryptionAlgorithm, key: &[u8; KEY_LENGTH], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| SecifyError::crypto(format!("Failed to create AES cipher: {}", e)))?;
            let nonce = Nonce::from_slice(nonce);
            cipher.decrypt(nonce, ciphertext)
                .map_err(|e| SecifyError::decryption(format!("Failed to decrypt with AES-256-GCM - incorrect password or corrupted file: {}", e)))
        }
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| SecifyError::crypto(format!("Failed to create ChaCha20 cipher: {}", e)))?;
            let nonce = ChaNonce::from_slice(nonce);
            cipher.decrypt(nonce, ciphertext)
                .map_err(|e| SecifyError::decryption(format!("Failed to decrypt with ChaCha20-Poly1305 - incorrect password or corrupted file: {}", e)))
        }
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| SecifyError::crypto(format!("Failed to create XChaCha20 cipher: {}", e)))?;
            let nonce = XNonce::from_slice(nonce);
            cipher.decrypt(nonce, ciphertext)
                .map_err(|e| SecifyError::decryption(format!("Failed to decrypt with XChaCha20-Poly1305 - incorrect password or corrupted file: {}", e)))
        }
    }
}

/// Decrypt chunked data for streaming decryption with fixed chunk sizes
pub fn decrypt_data_chunked(algorithm: &EncryptionAlgorithm, key: &[u8; KEY_LENGTH], base_nonce: &[u8], ciphertext: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut chunk_counter: u64 = 0;
    let mut offset = 0;
    
    while offset < ciphertext.len() {
        // Calculate current chunk size - try for full chunk_size, but accept smaller for last chunk
        let remaining_ciphertext = ciphertext.len() - offset;
        let current_chunk_size = remaining_ciphertext.min(chunk_size);
        
        // Extract chunk data
        let chunk_data = &ciphertext[offset..offset + current_chunk_size];
        
        // Create chunk nonce and decrypt
        let chunk_nonce = create_chunk_nonce(algorithm, base_nonce, chunk_counter)?;
        let decrypted_chunk = decrypt_data(algorithm, key, &chunk_nonce, chunk_data)?;
        
        result.extend_from_slice(&decrypted_chunk);
        
        offset += current_chunk_size;
        chunk_counter += 1;
    }
    
    Ok(result)
}

pub fn create_encryption_header(salt: &[u8], nonce: &[u8], algorithm: &EncryptionAlgorithm, argon2_params: &Argon2Params, chunk_size: u32) -> EncryptionHeader {
    let kdf = KeyDerivationConfig {
        algorithm: "Argon2id".to_owned(),
        version: "0x13".to_owned(),
        memory_cost: argon2_params.memory_kb(),
        time_cost: argon2_params.time_cost,
        parallelism: argon2_params.parallelism,
        output_length: KEY_LENGTH as u32,
    };
    
    EncryptionHeader {
        version: FILE_FORMAT_VERSION,
        encryption_algorithm: algorithm.to_string().to_owned(),
        kdf: Some(kdf),
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        chunk_size,
    }
}

pub fn create_payload_header(compression: Option<CompressionConfig>, archive: Option<String>) -> PayloadHeader {
    PayloadHeader {
        compression,
        archive,
    }
}

/// Generate base nonce for chunked encryption (shorter than full nonce to leave room for counter)
pub fn generate_base_nonce(algorithm: &EncryptionAlgorithm) -> Result<Vec<u8>> {
    let base_nonce_length = match algorithm {
        EncryptionAlgorithm::Aes256Gcm | EncryptionAlgorithm::ChaCha20Poly1305 => 8, // 8 bytes base + 4 bytes counter = 12 bytes total
        EncryptionAlgorithm::XChaCha20Poly1305 => 16, // 16 bytes base + 8 bytes counter = 24 bytes total
    };
    
    let mut base_nonce = vec![0u8; base_nonce_length];
    generate_secure_random_bytes(&mut base_nonce)?;
    Ok(base_nonce)
}

pub fn serialize_header_to_protobuf(header: &EncryptionHeader) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    header.encode(&mut buf)
        .map_err(|e| SecifyError::serialization(format!("Failed to encode protobuf: {}", e)))?;
    Ok(buf)
}

pub fn serialize_payload_header_to_protobuf(payload_header: &PayloadHeader) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    payload_header.encode(&mut buf)
        .map_err(|e| SecifyError::serialization(format!("Failed to encode payload header protobuf: {}", e)))?;
    Ok(buf)
}

pub fn deserialize_header_from_protobuf(data: &[u8]) -> Result<EncryptionHeader> {
    EncryptionHeader::decode(data)
        .map_err(|e| SecifyError::serialization(format!("Failed to decode protobuf: {}", e)))
}

pub fn deserialize_payload_header_from_protobuf(data: &[u8]) -> Result<PayloadHeader> {
    PayloadHeader::decode(data)
        .map_err(|e| SecifyError::serialization(format!("Failed to decode payload header protobuf: {}", e)))
}

pub fn validate_header(header: &EncryptionHeader) -> Result<()> {
    // Check version compatibility
    if header.version > FILE_FORMAT_VERSION {
        return Err(SecifyError::invalid_format(format!("Unsupported file format version: {}. This tool supports up to version {}.", 
              header.version, FILE_FORMAT_VERSION)));
    }
    
    // Validate encryption algorithm (parse to ensure it's supported)
    let algorithm = EncryptionAlgorithm::from_string(&header.encryption_algorithm)?;
    
    // Validate KDF
    let kdf = header.kdf.as_ref().ok_or_else(|| SecifyError::invalid_format("Missing KDF configuration"))?;
    if kdf.algorithm != "Argon2id" {
        return Err(SecifyError::invalid_format(format!("Unsupported key derivation function: {}", kdf.algorithm)));
    }
    
    // Validate salt and nonce lengths
    if header.salt.len() != SALT_LENGTH {
        return Err(SecifyError::invalid_format(format!("Invalid salt length: expected {}, got {}", SALT_LENGTH, header.salt.len())));
    }
    
    // Validate base nonce length for chunked encryption
    let expected_base_nonce_length = match algorithm {
        EncryptionAlgorithm::Aes256Gcm | EncryptionAlgorithm::ChaCha20Poly1305 => 8,
        EncryptionAlgorithm::XChaCha20Poly1305 => 16,
    };
    
    if header.nonce.len() != expected_base_nonce_length {
        return Err(SecifyError::invalid_format(format!("Invalid base nonce length for {} (chunked): expected {}, got {}", 
              algorithm.to_string(), expected_base_nonce_length, header.nonce.len())));
    }
    
    // Ensure chunk_size is valid for chunked encryption
    if header.chunk_size == 0 {
        return Err(SecifyError::invalid_config("Invalid chunk size: chunked encryption requires chunk_size > 0"));
    }
    
    Ok(())
}

pub fn validate_payload_header(payload_header: &PayloadHeader) -> Result<()> {
    // Validate compression configuration if present
    if let Some(compression) = &payload_header.compression {
        let compression_alg = CompressionAlgorithm::from_string(&compression.algorithm)?;
        match compression_alg {
            CompressionAlgorithm::None => {
                // No compression is always valid
            }
            CompressionAlgorithm::Zstd => {
                // zstd compression is always valid - level validation happens at compression time
            }
        }
    }
    
    Ok(())
}

/// Compute HMAC-SHA256 of plaintext data using key derived from password and salt
pub fn compute_hmac(plaintext: &[u8], key: &[u8; KEY_LENGTH], salt: &[u8]) -> Result<Vec<u8>> {
    type HmacSha256 = Hmac<Sha256>;
    
    // Create HMAC key by combining encryption key with salt
    let mut hmac_key = Vec::with_capacity(KEY_LENGTH + salt.len());
    hmac_key.extend_from_slice(key);
    hmac_key.extend_from_slice(salt);
    
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&hmac_key)
        .map_err(|e| SecifyError::crypto(format!("Failed to create HMAC: {}", e)))?;
    
    mac.update(plaintext);
    let result = mac.finalize();
    Ok(result.into_bytes().to_vec())
}

/// Verify HMAC-SHA256 of plaintext data
pub fn verify_hmac(plaintext: &[u8], key: &[u8; KEY_LENGTH], salt: &[u8], expected_hmac: &[u8]) -> Result<bool> {
    let computed_hmac = compute_hmac(plaintext, key, salt)?;
    Ok(computed_hmac == expected_hmac)
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

    fn create_test_base_nonce(algorithm: &EncryptionAlgorithm) -> Vec<u8> {
        match algorithm {
            EncryptionAlgorithm::Aes256Gcm | EncryptionAlgorithm::ChaCha20Poly1305 => vec![2u8; 8],
            EncryptionAlgorithm::XChaCha20Poly1305 => vec![2u8; 16],
        }
    }

    fn create_fast_test_params() -> Argon2Params {
        // Use minimal parameters for fast testing
        Argon2Params::new(8, 1, 1).unwrap() // 8MB memory, 1 iteration, 1 thread
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
        let params = create_fast_test_params();
        
        // Same password and salt should produce same key
        let key1 = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        let key2 = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        assert_eq!(key1, key2);
        
        // Different password should produce different key
        let key3 = derive_key("DifferentPassword", &salt, &params).unwrap();
        assert_ne!(key1, key3);
        
        // Different salt should produce different key
        let different_salt = [2u8; SALT_LENGTH];
        let key4 = derive_key(TEST_PASSWORD, &different_salt, &params).unwrap();
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_encrypt_decrypt_aes256gcm() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
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
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
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
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
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
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        // Encrypt with correct key
        let ciphertext = encrypt_data(&algorithm, &key, &nonce, TEST_DATA).unwrap();
        
        // Try to decrypt with wrong key
        let wrong_key = derive_key("WrongPassword", &salt, &params).unwrap();
        let result = decrypt_data(&algorithm, &wrong_key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_nonce_fails() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let nonce = create_test_nonce(&algorithm);
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
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
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        
        // Test file header (no archive field for single files)
        let header = create_encryption_header(&salt, &base_nonce, &algorithm, &params, DEFAULT_CHUNK_SIZE as u32);
        assert_eq!(header.version, FILE_FORMAT_VERSION);
        assert_eq!(header.encryption_algorithm, "XChaCha20-Poly1305");
        let kdf = header.kdf.as_ref().expect("KDF should be present");
        assert_eq!(kdf.algorithm, "Argon2id");
        assert_eq!(kdf.memory_cost, params.memory_kb());
        assert_eq!(kdf.time_cost, params.time_cost);
        assert_eq!(kdf.parallelism, params.parallelism);
        assert_eq!(header.salt, salt.to_vec());
        assert_eq!(header.nonce, base_nonce);
        assert_eq!(header.chunk_size, DEFAULT_CHUNK_SIZE as u32);
        
        // Test payload header creation
        let payload_header = create_payload_header(None, None);
        assert_eq!(payload_header.compression, None); // Single file has no compression
        assert_eq!(payload_header.archive, None); // Single file has no archive field
        
        // Test directory payload header with sec archive format
        let archive_payload_header = create_payload_header(None, Some("sec".to_string()));
        assert_eq!(archive_payload_header.compression, None);
        assert_eq!(archive_payload_header.archive, Some("sec".to_string())); // Directory has sec archive field
    }

    #[test]
    fn test_serialize_deserialize_header_protobuf() {
        let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let original_header = create_encryption_header(&salt, &base_nonce, &algorithm, &params, DEFAULT_CHUNK_SIZE as u32);
        
        // Serialize to protobuf
        let protobuf_data = serialize_header_to_protobuf(&original_header).unwrap();
        assert!(!protobuf_data.is_empty());
        
        // Deserialize from protobuf
        let deserialized_header = deserialize_header_from_protobuf(&protobuf_data).unwrap();
        
        // Compare fields
        assert_eq!(original_header.version, deserialized_header.version);
        assert_eq!(original_header.encryption_algorithm, deserialized_header.encryption_algorithm);
        assert_eq!(original_header.kdf.as_ref().unwrap().algorithm, deserialized_header.kdf.as_ref().unwrap().algorithm);
        assert_eq!(original_header.kdf.as_ref().unwrap().memory_cost, deserialized_header.kdf.as_ref().unwrap().memory_cost);
        assert_eq!(original_header.salt, deserialized_header.salt);
        assert_eq!(original_header.nonce, deserialized_header.nonce);
        assert_eq!(original_header.chunk_size, deserialized_header.chunk_size);
    }

    #[test]
    fn test_validate_header_success() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let header = create_encryption_header(&salt, &base_nonce, &algorithm, &params, DEFAULT_CHUNK_SIZE as u32);
        
        // Valid header should pass validation
        assert!(validate_header(&header).is_ok());
    }

    #[test]
    fn test_validate_header_invalid_version() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let mut header = create_encryption_header(&salt, &base_nonce, &algorithm, &params, DEFAULT_CHUNK_SIZE as u32);
        
        // Set invalid version
        header.version = FILE_FORMAT_VERSION + 1;
        assert!(validate_header(&header).is_err());
    }

    #[test]
    fn test_validate_header_invalid_algorithm() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let mut header = create_encryption_header(&salt, &base_nonce, &algorithm, &params, DEFAULT_CHUNK_SIZE as u32);
        
        // Set invalid algorithm
        header.encryption_algorithm = "Invalid-Algorithm".to_string();
        assert!(validate_header(&header).is_err());
    }

    #[test]
    fn test_validate_header_invalid_kdf() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let mut header = create_encryption_header(&salt, &base_nonce, &algorithm, &params, DEFAULT_CHUNK_SIZE as u32);
        
        // Set invalid KDF
        if let Some(ref mut kdf) = header.kdf {
            kdf.algorithm = "PBKDF2".to_string();
        }
        assert!(validate_header(&header).is_err());
    }

    #[test]
    fn test_validate_header_invalid_salt_length() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let mut header = create_encryption_header(&salt, &base_nonce, &algorithm, &params, DEFAULT_CHUNK_SIZE as u32);
        
        // Set invalid salt length
        header.salt = vec![1u8; 16]; // Wrong length
        assert!(validate_header(&header).is_err());
    }

    #[test]
    fn test_validate_header_invalid_nonce_length() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let mut header = create_encryption_header(&salt, &base_nonce, &algorithm, &params, DEFAULT_CHUNK_SIZE as u32);
        
        // Set invalid nonce length (AES-GCM expects 8-byte base nonce, so use 4 bytes to make it invalid)
        header.nonce = vec![2u8; 4]; // Wrong length for AES-GCM base nonce
        assert!(validate_header(&header).is_err());
    }

    #[test]
    fn test_encryption_algorithms_are_not_interchangeable() {
        let salt = create_test_salt();
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
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
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
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
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        // Create 1MB of test data
        let large_data = vec![0x42u8; 1024 * 1024];
        
        // Encrypt large data
        let ciphertext = encrypt_data(&algorithm, &key, &nonce, &large_data).unwrap();
        assert_ne!(ciphertext.len(), large_data.len());
        
        // Decrypt large data
        let plaintext = decrypt_data(&algorithm, &key, &nonce, &ciphertext).unwrap();
        assert_eq!(plaintext, large_data);
    }

    #[test]
    fn test_chunked_encryption_aes256gcm() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        let test_data = b"This is test data for chunked encryption with multiple chunks to verify it works correctly across chunk boundaries.";
        let chunk_size = 32; // Small chunk size to test multiple chunks
        
        // Encrypt data using chunked encryption
        let ciphertext = encrypt_data_chunked(&algorithm, &key, &base_nonce, test_data, chunk_size).unwrap();
        assert!(ciphertext.len() > test_data.len()); // Should be larger due to chunk headers and auth tags
        
        // Decrypt data using chunked decryption
        let plaintext = decrypt_data_chunked(&algorithm, &key, &base_nonce, &ciphertext, chunk_size).unwrap();
        assert_eq!(plaintext, test_data);
    }

    #[test]
    fn test_chunked_encryption_chacha20poly1305() {
        let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        let test_data = b"Another test for ChaCha20-Poly1305 chunked encryption functionality.";
        let chunk_size = 32; // Chunk size must be larger than auth tag size (16 bytes)
        
        // Encrypt data using chunked encryption
        let ciphertext = encrypt_data_chunked(&algorithm, &key, &base_nonce, test_data, chunk_size).unwrap();
        assert!(ciphertext.len() > test_data.len());
        
        // Decrypt data using chunked decryption
        let plaintext = decrypt_data_chunked(&algorithm, &key, &base_nonce, &ciphertext, chunk_size).unwrap();
        assert_eq!(plaintext, test_data);
    }

    #[test]
    fn test_chunked_encryption_xchacha20poly1305() {
        let algorithm = EncryptionAlgorithm::XChaCha20Poly1305;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        let test_data = b"Testing XChaCha20-Poly1305 with chunked encryption and larger data sets.";
        let chunk_size = DEFAULT_CHUNK_SIZE; // Use default chunk size
        
        // Encrypt data using chunked encryption
        let ciphertext = encrypt_data_chunked(&algorithm, &key, &base_nonce, test_data, chunk_size).unwrap();
        assert!(ciphertext.len() > test_data.len());
        
        // Decrypt data using chunked decryption
        let plaintext = decrypt_data_chunked(&algorithm, &key, &base_nonce, &ciphertext, chunk_size).unwrap();
        assert_eq!(plaintext, test_data);
    }

    #[test]
    fn test_chunked_encryption_empty_data() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        let empty_data = b"";
        let chunk_size = 1024;
        
        // Encrypt empty data using chunked encryption
        let ciphertext = encrypt_data_chunked(&algorithm, &key, &base_nonce, empty_data, chunk_size).unwrap();
        assert!(ciphertext.is_empty()); // Empty data should result in empty ciphertext for chunked encryption
        
        // Decrypt empty data using chunked decryption
        let plaintext = decrypt_data_chunked(&algorithm, &key, &base_nonce, &ciphertext, chunk_size).unwrap();
        assert_eq!(plaintext, empty_data);
    }

    #[test]
    fn test_chunked_encryption_single_chunk() {
        let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        let test_data = b"Small data that fits in one chunk";
        let chunk_size = 1024; // Much larger than test data
        
        // Encrypt data using chunked encryption (should create single chunk)
        let ciphertext = encrypt_data_chunked(&algorithm, &key, &base_nonce, test_data, chunk_size).unwrap();
        assert!(ciphertext.len() > test_data.len());
        
        // Decrypt data using chunked decryption
        let plaintext = decrypt_data_chunked(&algorithm, &key, &base_nonce, &ciphertext, chunk_size).unwrap();
        assert_eq!(plaintext, test_data);
    }

    #[test]
    fn test_chunked_encryption_zero_chunk_size_fails() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        let test_data = b"Test data";
        let chunk_size = 0; // Invalid chunk size
        
        // Should fail with zero chunk size
        let result = encrypt_data_chunked(&algorithm, &key, &base_nonce, test_data, chunk_size);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_hmac_consistency() {
        let salt = create_test_salt();
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        // Same data should produce same HMAC
        let hmac1 = compute_hmac(TEST_DATA, &key, &salt).unwrap();
        let hmac2 = compute_hmac(TEST_DATA, &key, &salt).unwrap();
        assert_eq!(hmac1, hmac2);
        
        // HMAC should be 32 bytes (SHA256)
        assert_eq!(hmac1.len(), 32);
        
        // Different data should produce different HMAC
        let different_data = b"Different test data";
        let hmac3 = compute_hmac(different_data, &key, &salt).unwrap();
        assert_ne!(hmac1, hmac3);
    }

    #[test]
    fn test_verify_hmac_success() {
        let salt = create_test_salt();
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        // Compute HMAC
        let hmac = compute_hmac(TEST_DATA, &key, &salt).unwrap();
        
        // Verify should succeed with correct HMAC
        assert!(verify_hmac(TEST_DATA, &key, &salt, &hmac).unwrap());
    }

    #[test]
    fn test_verify_hmac_failure() {
        let salt = create_test_salt();
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        // Compute HMAC for original data
        let hmac = compute_hmac(TEST_DATA, &key, &salt).unwrap();
        
        // Verify should fail with wrong data
        let wrong_data = b"Wrong test data";
        assert!(!verify_hmac(wrong_data, &key, &salt, &hmac).unwrap());
        
        // Verify should fail with wrong HMAC
        let mut wrong_hmac = hmac.clone();
        wrong_hmac[0] ^= 0x01; // Flip a bit
        assert!(!verify_hmac(TEST_DATA, &key, &salt, &wrong_hmac).unwrap());
        
        // Verify should fail with different key
        let different_salt = [2u8; SALT_LENGTH];
        let different_key = derive_key(TEST_PASSWORD, &different_salt, &params).unwrap();
        assert!(!verify_hmac(TEST_DATA, &different_key, &salt, &hmac).unwrap());
    }

    #[test]
    fn test_hmac_with_different_salts() {
        let salt1 = create_test_salt();
        let salt2 = [2u8; SALT_LENGTH]; // Different salt
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt1, &params).unwrap();
        
        // Same key but different salts should produce different HMACs
        let hmac1 = compute_hmac(TEST_DATA, &key, &salt1).unwrap();
        let hmac2 = compute_hmac(TEST_DATA, &key, &salt2).unwrap();
        assert_ne!(hmac1, hmac2);
        
        // Verify with wrong salt should fail
        assert!(!verify_hmac(TEST_DATA, &key, &salt2, &hmac1).unwrap());
    }

    #[test]
    fn test_hmac_empty_data() {
        let salt = create_test_salt();
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        // HMAC of empty data should work
        let empty_data = b"";
        let hmac = compute_hmac(empty_data, &key, &salt).unwrap();
        assert_eq!(hmac.len(), 32);
        assert!(verify_hmac(empty_data, &key, &salt, &hmac).unwrap());
    }

    #[test]
    fn test_hmac_large_data() {
        let salt = create_test_salt();
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        // Test with large data (1MB)
        let large_data = vec![0x42u8; 1024 * 1024];
        let hmac = compute_hmac(&large_data, &key, &salt).unwrap();
        assert_eq!(hmac.len(), 32);
        assert!(verify_hmac(&large_data, &key, &salt, &hmac).unwrap());
        
        // Modify one byte and verify it fails
        let mut modified_data = large_data.clone();
        modified_data[512 * 1024] ^= 0x01; // Flip a bit in the middle
        assert!(!verify_hmac(&modified_data, &key, &salt, &hmac).unwrap());
    }

    #[test]
    fn test_argon2_params_validation() {
        // Test valid parameters
        assert!(Argon2Params::new(8, 1, 1).is_ok());
        assert!(Argon2Params::new(64, 3, 4).is_ok());
        
        // Test invalid parameters (these should fail based on Argon2 constraints)
        assert!(Argon2Params::new(0, 1, 1).is_err()); // Zero memory
        assert!(Argon2Params::new(1, 0, 1).is_err()); // Zero time cost
        assert!(Argon2Params::new(1, 1, 0).is_err()); // Zero parallelism
    }

    #[test]
    fn test_argon2_params_memory_conversion() {
        let params = Argon2Params::new(64, 2, 2).unwrap();
        assert_eq!(params.memory_kb(), 64 * 1024); // Should convert MB to KB
    }

    #[test]
    fn test_generate_base_nonce_lengths() {
        // Test that base nonces have correct lengths for each algorithm
        let aes_base_nonce = generate_base_nonce(&EncryptionAlgorithm::Aes256Gcm).unwrap();
        assert_eq!(aes_base_nonce.len(), 8);
        
        let chacha_base_nonce = generate_base_nonce(&EncryptionAlgorithm::ChaCha20Poly1305).unwrap();
        assert_eq!(chacha_base_nonce.len(), 8);
        
        let xchacha_base_nonce = generate_base_nonce(&EncryptionAlgorithm::XChaCha20Poly1305).unwrap();
        assert_eq!(xchacha_base_nonce.len(), 16);
    }

    #[test]
    fn test_encryption_algorithm_auth_tag_size() {
        // All AEAD algorithms should have 16-byte authentication tags
        assert_eq!(EncryptionAlgorithm::Aes256Gcm.auth_tag_size(), 16);
        assert_eq!(EncryptionAlgorithm::ChaCha20Poly1305.auth_tag_size(), 16);
        assert_eq!(EncryptionAlgorithm::XChaCha20Poly1305.auth_tag_size(), 16);
    }

    #[test]
    fn test_chunked_encryption_boundary_conditions() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        // Test with chunk size exactly equal to auth tag size (should fail)
        let result = encrypt_data_chunked(&algorithm, &key, &base_nonce, TEST_DATA, 16);
        assert!(result.is_err());
        
        // Test with chunk size one byte larger than auth tag size (should work)
        let result = encrypt_data_chunked(&algorithm, &key, &base_nonce, TEST_DATA, 17);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_header_zero_chunk_size() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        let header = create_encryption_header(&salt, &base_nonce, &algorithm, &params, 0);
        
        // Zero chunk size should be invalid
        assert!(validate_header(&header).is_err());
    }

    #[test]
    fn test_protobuf_serialization_roundtrip_all_algorithms() {
        let algorithms = [
            EncryptionAlgorithm::Aes256Gcm,
            EncryptionAlgorithm::ChaCha20Poly1305,
            EncryptionAlgorithm::XChaCha20Poly1305,
        ];
        
        for algorithm in &algorithms {
            let salt = create_test_salt();
            let base_nonce = create_test_base_nonce(algorithm);
            let params = create_fast_test_params();
            let original_header = create_encryption_header(&salt, &base_nonce, algorithm, &params, DEFAULT_CHUNK_SIZE as u32);
            
            // Serialize and deserialize
            let protobuf_data = serialize_header_to_protobuf(&original_header).unwrap();
            let deserialized_header = deserialize_header_from_protobuf(&protobuf_data).unwrap();
            
            // Validate both headers
            assert!(validate_header(&original_header).is_ok());
            assert!(validate_header(&deserialized_header).is_ok());
            
            // Check algorithm-specific fields
            assert_eq!(original_header.encryption_algorithm, deserialized_header.encryption_algorithm);
            assert_eq!(original_header.nonce.len(), deserialized_header.nonce.len());
        }
    }

    #[test]
    fn test_content_type_archive_only() {
        // Test that single files don't have archive field, directories do
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = create_test_salt();
        let base_nonce = create_test_base_nonce(&algorithm);
        let params = create_fast_test_params();
        
        // Public header (encryption info only - no archive field)
        let public_header = create_encryption_header(&salt, &base_nonce, &algorithm, &params, DEFAULT_CHUNK_SIZE as u32);
        
        // Single file payload header (no archive field)
        let single_file_payload = create_payload_header(None, None);
        assert_eq!(single_file_payload.archive, None);
        
        // Directory payload header (with archive field)
        let directory_payload = create_payload_header(None, Some("sec".to_string()));
        assert_eq!(directory_payload.archive, Some("sec".to_string()));
        
        // Verify basic header fields are correct
        assert_eq!(public_header.version, FILE_FORMAT_VERSION);
        assert_eq!(public_header.encryption_algorithm, algorithm.to_string());
    }

    #[test]
    fn test_hmac_with_empty_salt() {
        let empty_salt = [0u8; SALT_LENGTH];
        let params = create_fast_test_params();
        let key = derive_key(TEST_PASSWORD, &empty_salt, &params).unwrap();
        
        // Should work with empty salt (all zeros)
        let hmac = compute_hmac(TEST_DATA, &key, &empty_salt).unwrap();
        assert_eq!(hmac.len(), 32);
        assert!(verify_hmac(TEST_DATA, &key, &empty_salt, &hmac).unwrap());
    }

    #[test]
    fn test_encryption_with_maximum_chunk_counter() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let base_nonce = create_test_base_nonce(&algorithm);
        
        // Test with maximum 32-bit counter value
        let max_counter = u32::MAX as u64;
        let result = create_chunk_nonce(&algorithm, &base_nonce, max_counter);
        assert!(result.is_ok());
        
        let nonce = result.unwrap();
        assert_eq!(nonce.len(), algorithm.nonce_length());
    }

}
