use std::fs::{self, File};
use std::path::Path;
use std::io::{Write, BufWriter};
use anyhow::{Result, Context, bail};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tar::Builder;

use crate::crypto::*;
use crate::progress::*;
use crate::tar_operations::{count_files_in_directory, stream_tar_directory_recursive, extract_tar_to_directory, extract_single_file_from_tar};

/// Size of the read buffer for streaming operations
const STREAM_BUFFER_SIZE: usize = 64 * 1024; // 64KB

/// A streaming encryption wrapper that encrypts data as it's written
pub struct StreamingEncryptionWriter<W: Write> {
    inner: W,
    algorithm: EncryptionAlgorithm,
    key: [u8; KEY_LENGTH],
    base_nonce: Vec<u8>,
    chunk_counter: u64,
    buffer: Vec<u8>,
    chunk_size: usize,
    hmac: Hmac<Sha256>,
}

impl<W: Write> StreamingEncryptionWriter<W> {
    pub fn new(
        inner: W,
        algorithm: EncryptionAlgorithm,
        key: [u8; KEY_LENGTH],
        base_nonce: Vec<u8>,
        salt: &[u8],
    ) -> Result<Self> {
        let auth_tag_size = algorithm.auth_tag_size();
        let chunk_size = DEFAULT_CHUNK_SIZE - auth_tag_size;
        
        // Create HMAC for integrity
        let mut hmac_key = Vec::with_capacity(KEY_LENGTH + salt.len());
        hmac_key.extend_from_slice(&key);
        hmac_key.extend_from_slice(salt);
        let hmac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key)
            .map_err(|e| anyhow::anyhow!("Failed to create HMAC: {}", e))?;
        
        Ok(Self {
            inner,
            algorithm,
            key,
            base_nonce,
            chunk_counter: 0,
            buffer: Vec::new(),
            chunk_size,
            hmac,
        })
    }
    
    fn flush_chunk(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        
        // Update HMAC with plaintext
        self.hmac.update(&self.buffer);
        
        // Create chunk nonce
        let chunk_nonce = create_streaming_chunk_nonce(&self.algorithm, &self.base_nonce, self.chunk_counter)?;
        
        // Encrypt the chunk
        let encrypted = encrypt_data(&self.algorithm, &self.key, &chunk_nonce, &self.buffer)?;
        
        // Write encrypted chunk
        self.inner.write_all(&encrypted)?;
        
        // Clear buffer and increment counter
        self.buffer.clear();
        self.chunk_counter += 1;
        
        Ok(())
    }
    
    pub fn finalize(mut self) -> Result<(W, Vec<u8>)> {
        // Flush any remaining data
        if !self.buffer.is_empty() {
            self.flush_chunk()?;
        }
        
        // Get final HMAC
        let hmac_result = self.hmac.finalize();
        let hmac_bytes = hmac_result.into_bytes().to_vec();
        
        // Write HMAC to the end
        self.inner.write_all(&hmac_bytes)?;
        
        Ok((self.inner, hmac_bytes))
    }
}

impl<W: Write> Write for StreamingEncryptionWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut bytes_written = 0;
        let mut remaining = buf;
        
        while !remaining.is_empty() {
            let space_in_buffer = self.chunk_size - self.buffer.len();
            let bytes_to_copy = remaining.len().min(space_in_buffer);
            
            self.buffer.extend_from_slice(&remaining[..bytes_to_copy]);
            remaining = &remaining[bytes_to_copy..];
            bytes_written += bytes_to_copy;
            
            // If buffer is full, flush it
            if self.buffer.len() == self.chunk_size {
                self.flush_chunk()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            }
        }
        
        Ok(bytes_written)
    }
    
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Create a chunk nonce for streaming encryption/decryption
fn create_streaming_chunk_nonce(algorithm: &EncryptionAlgorithm, base_nonce: &[u8], chunk_counter: u64) -> Result<Vec<u8>> {
    let nonce_length = algorithm.nonce_length();
    let mut chunk_nonce = vec![0u8; nonce_length];
    
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm | EncryptionAlgorithm::ChaCha20Poly1305 => {
            if base_nonce.len() != 8 {
                bail!("Base nonce for {}/ChaCha20 must be 8 bytes, got {}", 
                      algorithm.to_string(), base_nonce.len());
            }
            chunk_nonce[..8].copy_from_slice(base_nonce);
            chunk_nonce[8..12].copy_from_slice(&(chunk_counter as u32).to_le_bytes());
        }
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            if base_nonce.len() != 16 {
                bail!("Base nonce for XChaCha20 must be 16 bytes, got {}", base_nonce.len());
            }
            chunk_nonce[..16].copy_from_slice(base_nonce);
            chunk_nonce[16..24].copy_from_slice(&chunk_counter.to_le_bytes());
        }
    }
    
    Ok(chunk_nonce)
}

/// Stream encrypt any file or directory using a full read → tar → encrypt → write pipeline
/// This unified function handles both files and directories by putting them in a TAR archive
pub fn stream_encrypt_tar(
    input_path: &str,
    output_path: &str,
    password: &str,
    algorithm: &EncryptionAlgorithm,
    argon2_params: &Argon2Params,
) -> Result<()> {
    let input_path_obj = Path::new(input_path);
    
    if !input_path_obj.exists() {
        bail!("Input path does not exist: {}", input_path);
    }
    
    let is_directory = input_path_obj.is_dir();
    
    if is_directory {
        println!("Streaming directory encryption with full pipeline (TAR)...");
    } else {
        println!("Streaming file encryption with TAR archive format...");
    }
    
    // Generate cryptographic parameters
    let mut salt = [0u8; SALT_LENGTH];
    generate_secure_random_bytes(&mut salt)?;
    let base_nonce = generate_base_nonce(algorithm)?;
    let key = derive_key(password, &salt, argon2_params)?;
    
    // Create header - always mark as TAR format
    let header = create_encryption_header(&salt, &base_nonce, algorithm, argon2_params, DEFAULT_CHUNK_SIZE as u32);
    let cbor_header = serialize_header_to_cbor(&header)?;
    
    // Create output file
    let output_file = File::create(output_path)
        .with_context(|| format!("Failed to create output file: {}", output_path))?;
    
    let mut buffered_output = BufWriter::with_capacity(STREAM_BUFFER_SIZE, output_file);
    
    // Write header length and header
    buffered_output.write_all(&(cbor_header.len() as u32).to_le_bytes())?;
    buffered_output.write_all(&cbor_header)?;
    
    // Create streaming encryption wrapper
    let encryption_writer = StreamingEncryptionWriter::new(
        buffered_output,
        algorithm.clone(),
        key,
        base_nonce,
        &salt,
    )?;
    
    // Create streaming TAR builder (fully streaming, no seeking required)
    let mut tar_builder = Builder::new(encryption_writer);
    
    if is_directory {
        // Count files for progress tracking
        println!("Counting files...");
        let total_files = count_files_in_directory(input_path_obj)?;
        let progress_bar = create_standard_progress_bar(total_files, "Streaming TAR");
        
        // Process directory recursively with streaming TAR
        let mut processed_files = 0;
        stream_tar_directory_recursive(
            input_path_obj,
            input_path_obj,
            &mut tar_builder,
            &progress_bar,
            &mut processed_files
        )?;        progress_bar.finish_with_message("Streaming directory encryption complete");
    } else {
        // Handle single file - add it to TAR archive
        println!("Adding file to TAR archive...");
        let file_name = input_path_obj.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid file name"))?;
        
        let mut file = File::open(input_path)
            .with_context(|| format!("Failed to open file: {}", input_path))?;
        
        tar_builder.append_file(file_name, &mut file)
            .with_context(|| format!("Failed to add file to tar: {}", file_name))?;
        
        println!("File added to TAR archive");
    }
    
    // Finalize TAR and get the underlying encryption writer
    let encryption_writer = tar_builder.into_inner()
        .context("Failed to finish TAR archive")?;
    
    // Finalize encryption and get the underlying writer
    let (mut final_output, _hmac_bytes) = encryption_writer.finalize()?;
    
    // Flush the final output
    final_output.flush()
        .context("Failed to flush output file")?;
    
    if is_directory {
        println!("Directory encrypted successfully: {}", output_path);
    } else {
        println!("File encrypted successfully: {}", output_path);
    }
    
    Ok(())
}

/// Stream decrypt a TAR-based encrypted file, handling both single files and directories
pub fn stream_decrypt_tar(
    input_path: &str,
    output_path: &str,
    password: &str,
) -> Result<()> {
    // Read the encrypted file
    let encrypted_data = fs::read(input_path)
        .with_context(|| format!("Failed to read encrypted file: {}", input_path))?;
    
    // Check minimum file size (header length + some header + at least some ciphertext)
    if encrypted_data.len() < 4 + 10 + 16 {
        bail!("Invalid encrypted file format - file too small");
    }
    
    // Extract CBOR header length (first 4 bytes, little-endian)
    let header_length_bytes = [
        encrypted_data[0], encrypted_data[1], encrypted_data[2], encrypted_data[3]
    ];
    let header_length = u32::from_le_bytes(header_length_bytes) as usize;
    
    // Validate header length with comprehensive bounds checking
    if header_length == 0 {
        bail!("Invalid CBOR header: header length is zero");
    }
    if header_length > encrypted_data.len().saturating_sub(4) {
        bail!("Invalid CBOR header length: {} bytes (file size: {} bytes)", 
              header_length, encrypted_data.len());
    }
    if header_length > 1_048_576 { // 1MB header size limit
        bail!("CBOR header too large: {} bytes (maximum: 1MB)", header_length);
    }
    
    // Extract CBOR header and ciphertext
    let cbor_header_data = &encrypted_data[4..4 + header_length];
    let remaining_data = &encrypted_data[4 + header_length..];
    
    // Extract HMAC (last 32 bytes) and ciphertext (everything before HMAC)
    if remaining_data.len() < 32 {
        bail!("Invalid encrypted file format - missing HMAC");
    }
    let ciphertext = &remaining_data[..remaining_data.len() - 32];
    let stored_hmac = &remaining_data[remaining_data.len() - 32..];
    
    // Deserialize and validate header
    let header = deserialize_header_from_cbor(cbor_header_data)?;
    validate_header(&header)?;
    
    // Display encryption details
    println!("File format version: {}", header.version);
    println!("Encryption: {}", header.encryption_algorithm);
    println!("Key derivation: {} ({}MB, {} iterations, {} threads)", 
             header.kdf.algorithm, 
             header.kdf.memory_cost / 1024,
             header.kdf.time_cost,
             header.kdf.parallelism);
    println!("Chunked encryption: {}KB chunks", header.chunk_size / 1024);
    
    // Parse the encryption algorithm from header
    let algorithm = EncryptionAlgorithm::from_string(&header.encryption_algorithm)?;
    
    // Extract Argon2 parameters from header
    let argon2_params = Argon2Params::new(
        header.kdf.memory_cost / 1024, // Convert KB back to MB
        header.kdf.time_cost,
        header.kdf.parallelism,
    )?;
    
    // Derive decryption key from password and salt from header
    let key = derive_key(password, &header.salt, &argon2_params)?;
    
    // Decrypt the data using chunked decryption
    println!("Decrypting data...");
    let decrypt_pb = create_byte_progress_bar(ciphertext.len() as u64, "Decrypting");
    
    let plaintext = decrypt_data_chunked(&algorithm, &key, &header.nonce, ciphertext, header.chunk_size as usize)?;
    
    decrypt_pb.inc(ciphertext.len() as u64);
    decrypt_pb.finish_with_message("Decryption complete");
    
    // Verify HMAC for file integrity
    println!("Verifying file integrity...");
    if !verify_hmac(&plaintext, &key, &header.salt, stored_hmac)? {
        bail!("File integrity verification failed - file may be corrupted or tampered with");
    }
    println!("File integrity verified successfully");
    
    // Extract TAR archive and determine if it's a single file or directory
    let tar_cursor = std::io::Cursor::new(&plaintext);
    let mut tar_archive = tar::Archive::new(tar_cursor);
    let entries: Result<Vec<_>, _> = tar_archive.entries()?.collect();
    let entries = entries.context("Failed to read TAR entries")?;
    
    if entries.len() == 1 {
        // Single file in TAR - extract to the output path directly
        extract_single_file_from_tar(&plaintext, output_path)?;
    } else {
        // Multiple files/directories - extract to directory
        // Check if output directory already exists
        if Path::new(output_path).exists() {
            bail!("Output directory already exists: {}", output_path);
        }
        
        // Create the output directory
        fs::create_dir_all(output_path)
            .with_context(|| format!("Failed to create output directory: {}", output_path))?;
        
        // Extract the decrypted data to the directory
        println!("Extracting TAR directory...");
        extract_tar_to_directory(&plaintext, Path::new(output_path))?;
        
        println!("Directory decrypted and extracted successfully: {}", output_path);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    
    // Test constants
    const TEST_PASSWORD: &str = "TestPassword123!";
    const TEST_DATA: &[u8] = b"Hello, streaming world! This is test data for streaming encryption.";
    
    fn create_test_argon2_params() -> Argon2Params {
        // Fast parameters for testing
        Argon2Params::new(8, 1, 1).unwrap()
    }

    #[test]
    fn test_streaming_encryption_writer_basic() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let salt = [1u8; SALT_LENGTH];
        let base_nonce = vec![2u8; 8]; // 8 bytes for AES-256-GCM
        let params = create_test_argon2_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        let output = Vec::new();
        let mut writer = StreamingEncryptionWriter::new(
            output,
            algorithm,
            key,
            base_nonce,
            &salt,
        ).unwrap();
        
        // Write test data
        writer.write_all(TEST_DATA).unwrap();
        
        // Finalize and get output
        let (encrypted_output, hmac_bytes) = writer.finalize().unwrap();
        
        // Verify output is not empty and includes HMAC
        assert!(!encrypted_output.is_empty());
        assert_eq!(hmac_bytes.len(), 32); // SHA256 HMAC length
        assert!(encrypted_output.len() > TEST_DATA.len()); // Should be larger due to encryption overhead
    }

    #[test]
    fn test_streaming_encryption_writer_chunked_writes() {
        let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
        let salt = [3u8; SALT_LENGTH];
        let base_nonce = vec![4u8; 8];
        let params = create_test_argon2_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        let output = Vec::new();
        let mut writer = StreamingEncryptionWriter::new(
            output,
            algorithm,
            key,
            base_nonce,
            &salt,
        ).unwrap();
        
        // Write data in small chunks to test chunking logic
        let chunk_size = 16;
        for chunk in TEST_DATA.chunks(chunk_size) {
            writer.write_all(chunk).unwrap();
        }
        
        let (encrypted_output, _) = writer.finalize().unwrap();
        assert!(!encrypted_output.is_empty());
    }

    #[test]
    fn test_streaming_encryption_writer_empty_data() {
        let algorithm = EncryptionAlgorithm::XChaCha20Poly1305;
        let salt = [5u8; SALT_LENGTH];
        let base_nonce = vec![6u8; 16]; // 16 bytes for XChaCha20
        let params = create_test_argon2_params();
        let key = derive_key(TEST_PASSWORD, &salt, &params).unwrap();
        
        let output = Vec::new();
        let writer = StreamingEncryptionWriter::new(
            output,
            algorithm,
            key,
            base_nonce,
            &salt,
        ).unwrap();
        
        // Finalize without writing any data
        let (encrypted_output, hmac_bytes) = writer.finalize().unwrap();
        
        // Should still have HMAC even with no data
        assert_eq!(hmac_bytes.len(), 32);
        // Output should contain the HMAC
        assert_eq!(encrypted_output.len(), 32);
    }

    #[test]
    fn test_create_streaming_chunk_nonce() {
        // Test AES-256-GCM nonce creation
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let base_nonce = vec![1u8; 8];
        
        let nonce1 = create_streaming_chunk_nonce(&algorithm, &base_nonce, 0).unwrap();
        let nonce2 = create_streaming_chunk_nonce(&algorithm, &base_nonce, 1).unwrap();
        
        assert_eq!(nonce1.len(), 12); // AES-GCM nonce length
        assert_eq!(nonce2.len(), 12);
        assert_ne!(nonce1, nonce2); // Different counters should produce different nonces
        
        // Check base nonce is preserved
        assert_eq!(&nonce1[..8], &base_nonce[..]);
        assert_eq!(&nonce2[..8], &base_nonce[..]);
    }

    #[test]
    fn test_create_streaming_chunk_nonce_xchacha20() {
        // Test XChaCha20-Poly1305 nonce creation
        let algorithm = EncryptionAlgorithm::XChaCha20Poly1305;
        let base_nonce = vec![2u8; 16];
        
        let nonce1 = create_streaming_chunk_nonce(&algorithm, &base_nonce, 0).unwrap();
        let nonce2 = create_streaming_chunk_nonce(&algorithm, &base_nonce, 100).unwrap();
        
        assert_eq!(nonce1.len(), 24); // XChaCha20 nonce length
        assert_eq!(nonce2.len(), 24);
        assert_ne!(nonce1, nonce2);
        
        // Check base nonce is preserved
        assert_eq!(&nonce1[..16], &base_nonce[..]);
        assert_eq!(&nonce2[..16], &base_nonce[..]);
    }

    #[test]
    fn test_create_streaming_chunk_nonce_invalid_base() {
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let invalid_base_nonce = vec![1u8; 4]; // Wrong length for AES-GCM
        
        let result = create_streaming_chunk_nonce(&algorithm, &invalid_base_nonce, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_stream_encrypt_decrypt_file_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test_input.txt");
        let encrypted_file = temp_dir.path().join("test_output.sec");
        let decrypted_file = temp_dir.path().join("test_decrypted.txt");
        
        // Create test input file
        fs::write(&input_file, TEST_DATA).unwrap();
        
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let params = create_test_argon2_params();
        
        // Encrypt the file
        stream_encrypt_tar(
            input_file.to_str().unwrap(),
            encrypted_file.to_str().unwrap(),
            TEST_PASSWORD,
            &algorithm,
            &params,
        ).unwrap();
        
        // Verify encrypted file exists and is different from input
        assert!(encrypted_file.exists());
        let encrypted_data = fs::read(&encrypted_file).unwrap();
        assert_ne!(encrypted_data, TEST_DATA);
        assert!(encrypted_data.len() > TEST_DATA.len());
        
        // Decrypt the file
        stream_decrypt_tar(
            encrypted_file.to_str().unwrap(),
            decrypted_file.to_str().unwrap(),
            TEST_PASSWORD,
        ).unwrap();
        
        // Verify decrypted file matches original
        assert!(decrypted_file.exists());
        let decrypted_data = fs::read(&decrypted_file).unwrap();
        assert_eq!(decrypted_data, TEST_DATA);
    }

    #[test]
    fn test_stream_encrypt_decrypt_wrong_password() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test_input.txt");
        let encrypted_file = temp_dir.path().join("test_output.sec");
        let decrypted_file = temp_dir.path().join("test_decrypted.txt");
        
        fs::write(&input_file, TEST_DATA).unwrap();
        
        let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
        let params = create_test_argon2_params();
        
        // Encrypt with one password
        stream_encrypt_tar(
            input_file.to_str().unwrap(),
            encrypted_file.to_str().unwrap(),
            TEST_PASSWORD,
            &algorithm,
            &params,
        ).unwrap();
        
        // Try to decrypt with wrong password
        let result = stream_decrypt_tar(
            encrypted_file.to_str().unwrap(),
            decrypted_file.to_str().unwrap(),
            "WrongPassword",
        );
        
        // Should fail with wrong password
        assert!(result.is_err());
        assert!(!decrypted_file.exists());
    }

    #[test]
    fn test_stream_encrypt_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent_file = temp_dir.path().join("nonexistent.txt");
        let output_file = temp_dir.path().join("output.sec");
        
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let params = create_test_argon2_params();
        
        let result = stream_encrypt_tar(
            nonexistent_file.to_str().unwrap(),
            output_file.to_str().unwrap(),
            TEST_PASSWORD,
            &algorithm,
            &params,
        );
        
        assert!(result.is_err());
        assert!(!output_file.exists());
    }

    #[test]
    fn test_stream_decrypt_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let invalid_encrypted_file = temp_dir.path().join("invalid.sec");
        let output_file = temp_dir.path().join("output.txt");
        
        // Create invalid encrypted file (too small)
        fs::write(&invalid_encrypted_file, b"invalid").unwrap();
        
        let result = stream_decrypt_tar(
            invalid_encrypted_file.to_str().unwrap(),
            output_file.to_str().unwrap(),
            TEST_PASSWORD,
        );
        
        assert!(result.is_err());
        assert!(!output_file.exists());
    }

    #[test]
    fn test_stream_decrypt_corrupted_header() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test_input.txt");
        let encrypted_file = temp_dir.path().join("test_output.sec");
        let decrypted_file = temp_dir.path().join("test_decrypted.txt");
        
        fs::write(&input_file, TEST_DATA).unwrap();
        
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let params = create_test_argon2_params();
        
        // Encrypt file normally
        stream_encrypt_tar(
            input_file.to_str().unwrap(),
            encrypted_file.to_str().unwrap(),
            TEST_PASSWORD,
            &algorithm,
            &params,
        ).unwrap();
        
        // Corrupt the header by modifying the header length
        let mut encrypted_data = fs::read(&encrypted_file).unwrap();
        encrypted_data[0] = 0xFF; // Corrupt first byte of header length
        fs::write(&encrypted_file, &encrypted_data).unwrap();
        
        // Try to decrypt corrupted file
        let result = stream_decrypt_tar(
            encrypted_file.to_str().unwrap(),
            decrypted_file.to_str().unwrap(),
            TEST_PASSWORD,
        );
        
        assert!(result.is_err());
    }

    #[test]
    fn test_all_encryption_algorithms_streaming() {
        let algorithms = [
            EncryptionAlgorithm::Aes256Gcm,
            EncryptionAlgorithm::ChaCha20Poly1305,
            EncryptionAlgorithm::XChaCha20Poly1305,
        ];
        
        for algorithm in &algorithms {
            let temp_dir = TempDir::new().unwrap();
            let input_file = temp_dir.path().join("test_input.txt");
            let encrypted_file = temp_dir.path().join("test_output.sec");
            let decrypted_file = temp_dir.path().join("test_decrypted.txt");
            
            fs::write(&input_file, TEST_DATA).unwrap();
            
            let params = create_test_argon2_params();
            
            // Test encryption/decryption roundtrip for each algorithm
            stream_encrypt_tar(
                input_file.to_str().unwrap(),
                encrypted_file.to_str().unwrap(),
                TEST_PASSWORD,
                algorithm,
                &params,
            ).unwrap();
            
            stream_decrypt_tar(
                encrypted_file.to_str().unwrap(),
                decrypted_file.to_str().unwrap(),
                TEST_PASSWORD,
            ).unwrap();
            
            let decrypted_data = fs::read(&decrypted_file).unwrap();
            assert_eq!(decrypted_data, TEST_DATA, "Failed for algorithm: {:?}", algorithm);
        }
    }
}
