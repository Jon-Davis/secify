//! Core streaming encryption/decryption functionality without UI dependencies
//! 
//! This module provides the pure business logic for creating and reading .sec files,
//! separated from progress reporting and console output.

use std::fs::{self, File};
use std::path::Path;
use std::io::{Read, Write, BufReader, BufWriter, Seek};
use anyhow::{Result, Context, bail};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tar::Builder;
use zstd;

use crate::crypto::*;

/// Size of the read buffer for streaming operations
const STREAM_BUFFER_SIZE: usize = 64 * 1024; // 64KB

/// Maximum allowed CBOR header size (1MB)
const MAX_HEADER_SIZE: usize = 1_048_576;

/// HMAC size in bytes (SHA256)
const HMAC_SIZE: usize = 32;

/// Progress callback for encryption operations
pub type EncryptProgressCallback<'a> = &'a dyn Fn(EncryptProgress);

/// Progress callback for decryption operations  
pub type DecryptProgressCallback<'a> = &'a dyn Fn(DecryptProgress);

/// Logging callback for informational messages
pub type LogCallback<'a> = &'a dyn Fn(&str);

/// Progress information during encryption
#[derive(Debug, Clone)]
pub enum EncryptProgress {
    /// Starting operation
    Starting { is_directory: bool, has_compression: bool },
    /// Counting files in directory
    CountingFiles,
    /// File counting complete
    FileCountComplete { total_files: u64 },
    /// Processing a file or directory
    ProcessingFile { current: u64, total: u64, name: String },
    /// Encryption pipeline started
    EncryptionStarted,
    /// Encryption complete
    EncryptionComplete,
}

/// Progress information during decryption
#[derive(Debug, Clone)]
pub enum DecryptProgress {
    /// Header validation complete, starting decryption
    DecryptionStarted { 
        encryption_info: EncryptionInfo,
        total_bytes: u64,
    },
    /// Bytes processed during decryption/extraction
    BytesProcessed { current: u64, total: u64 },
    /// Extraction type determined
    ExtractionStrategy { is_single_file: bool, output_path: String },
    /// HMAC verification started
    VerifyingIntegrity,
    /// Decryption and extraction complete
    DecryptionComplete,
}

/// Encryption information extracted from header
#[derive(Debug, Clone)]
pub struct EncryptionInfo {
    pub version: u32,
    pub algorithm: String,
    pub compression: Option<String>,
    pub kdf_info: String,
    pub chunk_size: u32,
}

/// Core streaming encryption writer without UI dependencies
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

/// Core streaming decryption reader with progress callback
pub struct StreamingDecryptionReader<R: Read> {
    inner: R,
    algorithm: EncryptionAlgorithm,
    key: [u8; KEY_LENGTH],
    base_nonce: Vec<u8>,
    chunk_counter: u64,
    chunk_size: usize,
    buffer: Vec<u8>,
    buffer_pos: usize,
    hmac: Hmac<Sha256>,
    hmac_buffer: Vec<u8>,
    total_read: u64,
    file_size: u64,
    finished: bool,
}

impl<R: Read> StreamingDecryptionReader<R> {
    pub fn new(
        inner: R,
        algorithm: EncryptionAlgorithm,
        key: [u8; KEY_LENGTH],
        base_nonce: Vec<u8>,
        salt: &[u8],
        file_size: u64,
    ) -> Result<Self> {
        let chunk_size = DEFAULT_CHUNK_SIZE;
        
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
            chunk_size,
            buffer: Vec::new(),
            buffer_pos: 0,
            hmac,
            hmac_buffer: Vec::new(),
            total_read: 0,
            file_size: file_size.saturating_sub(HMAC_SIZE as u64), // Subtract HMAC size
            finished: false,
        })
    }
    
    fn decrypt_next_chunk(&mut self) -> Result<bool> {
        if self.finished || self.total_read >= self.file_size {
            return Ok(false);
        }
        
        // Read next encrypted chunk
        let mut encrypted_chunk = vec![0u8; self.chunk_size];
        let bytes_to_read = (self.file_size - self.total_read).min(self.chunk_size as u64) as usize;
        encrypted_chunk.resize(bytes_to_read, 0);
        
        let mut bytes_read = 0;
        while bytes_read < bytes_to_read {
            match self.inner.read(&mut encrypted_chunk[bytes_read..]) {
                Ok(0) => break, // EOF
                Ok(n) => bytes_read += n,
                Err(e) => return Err(anyhow::anyhow!("Failed to read encrypted chunk: {}", e)),
            }
        }
        
        if bytes_read == 0 {
            self.finished = true;
            return Ok(false);
        }
        
        encrypted_chunk.truncate(bytes_read);
        self.total_read += bytes_read as u64;
        
        // Create chunk nonce
        let chunk_nonce = create_streaming_chunk_nonce(&self.algorithm, &self.base_nonce, self.chunk_counter)?;
        
        // Decrypt the chunk
        let plaintext = decrypt_data(&self.algorithm, &self.key, &chunk_nonce, &encrypted_chunk)?;
        
        // Update HMAC with plaintext
        self.hmac.update(&plaintext);
        
        // Store decrypted data in buffer
        self.buffer = plaintext;
        self.buffer_pos = 0;
        self.chunk_counter += 1;
        
        Ok(true)
    }
    
    pub fn verify_hmac(&mut self, expected_hmac: &[u8]) -> Result<bool> {
        // Read any remaining HMAC bytes if we haven't finished reading the file
        if !self.finished && self.total_read < self.file_size {
            // Read and discard remaining ciphertext
            let mut temp_buffer = vec![0u8; 4096];
            while self.total_read < self.file_size {
                match self.inner.read(&mut temp_buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        let bytes_to_process = (self.file_size - self.total_read).min(n as u64) as usize;
                        self.total_read += bytes_to_process as u64;
                    }
                    Err(e) => return Err(anyhow::anyhow!("Failed to read remaining data: {}", e)),
                }
            }
        }
        
        // Read HMAC from end of file
        self.hmac_buffer.resize(HMAC_SIZE, 0);
        let mut hmac_bytes_read = 0;
        while hmac_bytes_read < HMAC_SIZE {
            match self.inner.read(&mut self.hmac_buffer[hmac_bytes_read..]) {
                Ok(0) => break,
                Ok(n) => hmac_bytes_read += n,
                Err(e) => return Err(anyhow::anyhow!("Failed to read HMAC: {}", e)),
            }
        }
        
        if hmac_bytes_read != HMAC_SIZE {
            return Err(anyhow::anyhow!("Incomplete HMAC read: expected {} bytes, got {}", HMAC_SIZE, hmac_bytes_read));
        }
        
        // Verify HMAC
        let computed_hmac = self.hmac.clone().finalize().into_bytes();
        Ok(computed_hmac.as_slice() == expected_hmac)
    }
}

impl<R: Read> Read for StreamingDecryptionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.finished {
            return Ok(0);
        }
        
        // If buffer is empty or exhausted, decrypt next chunk
        if self.buffer_pos >= self.buffer.len() {
            match self.decrypt_next_chunk() {
                Ok(true) => {}, // Successfully decrypted a chunk
                Ok(false) => {
                    self.finished = true;
                    return Ok(0); // EOF
                },
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        }
        
        // Copy data from buffer to output
        let bytes_available = self.buffer.len() - self.buffer_pos;
        let bytes_to_copy = buf.len().min(bytes_available);
        
        buf[..bytes_to_copy].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + bytes_to_copy]);
        self.buffer_pos += bytes_to_copy;
        
        Ok(bytes_to_copy)
    }
}

/// Compression wrapper without UI dependencies
pub struct CompressionBufferingWriter<W: Write> {
    inner: StreamingEncryptionWriter<W>,
    compression_buffer: Vec<u8>,
    compression_encoder: Option<zstd::Encoder<'static, Vec<u8>>>,
    chunk_size: usize,
}

impl<W: Write> CompressionBufferingWriter<W> {
    pub fn new(
        inner: StreamingEncryptionWriter<W>,
        compression: Option<&CompressionConfig>,
    ) -> Result<Self> {
        let chunk_size = DEFAULT_CHUNK_SIZE - 16; // Account for auth tag
        
        let compression_encoder = if let Some(config) = compression {
            match CompressionAlgorithm::from_string(&config.algorithm)? {
                CompressionAlgorithm::None => None,
                CompressionAlgorithm::Zstd => {
                    let encoder = zstd::Encoder::new(Vec::new(), config.level)?;
                    Some(encoder)
                }
            }
        } else {
            None
        };
        
        Ok(Self {
            inner,
            compression_buffer: Vec::new(),
            compression_encoder,
            chunk_size,
        })
    }
    
    /// Helper method to handle compression output and buffer management
    fn handle_compression_output(&mut self) -> Result<()> {
        if let Some(ref mut encoder) = self.compression_encoder {
            let compressed_output = encoder.get_ref();
            if !compressed_output.is_empty() {
                self.compression_buffer.extend_from_slice(compressed_output);
                *encoder.get_mut() = Vec::new();
                self.flush_compressed_chunks()?;
            }
        }
        Ok(())
    }
    
    fn flush_compressed_chunks(&mut self) -> Result<()> {
        // Extract full chunks from compression buffer and send to encryption
        while self.compression_buffer.len() >= self.chunk_size {
            let chunk = self.compression_buffer.drain(..self.chunk_size).collect::<Vec<u8>>();
            self.inner.write_all(&chunk)?;
        }
        Ok(())
    }
    
    pub fn finalize(mut self) -> Result<StreamingEncryptionWriter<W>> {
        // Finalize compression if enabled
        if let Some(encoder) = self.compression_encoder.take() {
            let final_compressed = encoder.finish()?;
            self.compression_buffer.extend_from_slice(&final_compressed);
        }
        
        // Flush all remaining compressed data
        if !self.compression_buffer.is_empty() {
            self.inner.write_all(&self.compression_buffer)?;
        }
        
        Ok(self.inner)
    }
}

impl<W: Write> Write for CompressionBufferingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(ref mut encoder) = self.compression_encoder {
            // Write to the compression encoder (it implements Write trait)
            encoder.write_all(buf)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            
            // Handle compression output using helper method
            self.handle_compression_output()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        } else {
            // No compression - pass through directly to encryption
            self.inner.write(buf)?;
        }
        
        Ok(buf.len())
    }
    
    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(ref mut encoder) = self.compression_encoder {
            // Flush compression encoder
            encoder.flush()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            
            // Handle compression output using helper method
            self.handle_compression_output()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        }
        
        self.inner.flush()
    }
}

/// Core encryption function without UI dependencies
pub fn encrypt_core<P, L>(
    input_path: &str,
    output_path: &str,
    password: &str,
    algorithm: &EncryptionAlgorithm,
    argon2_params: &Argon2Params,
    compression: Option<CompressionConfig>,
    progress_callback: &P,
    log_callback: &L,
) -> Result<()>
where
    P: Fn(EncryptProgress),
    L: Fn(&str),
{
    let input_path_obj = Path::new(input_path);
    if !input_path_obj.exists() {
        bail!("Input path does not exist: {}", input_path);
    }
    let is_directory = input_path_obj.is_dir();

    // Report operation type
    progress_callback(EncryptProgress::Starting { 
        is_directory, 
        has_compression: compression.is_some() 
    });

    // Generate cryptographic parameters
    let mut salt = [0u8; SALT_LENGTH];
    generate_secure_random_bytes(&mut salt)?;
    let base_nonce = generate_base_nonce(algorithm)?;
    let key = derive_key_with_callback(password, &salt, argon2_params, log_callback)?;

    // Create header - always mark as TAR format
    let header = create_encryption_header(&salt, &base_nonce, algorithm, argon2_params, DEFAULT_CHUNK_SIZE as u32, compression.clone());
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

    progress_callback(EncryptProgress::EncryptionStarted);

    // Create writer chain based on compression setting
    if compression.is_some() {
        let compression_writer = CompressionBufferingWriter::new(encryption_writer, compression.as_ref())?;
        let mut tar_builder = Builder::new(compression_writer);
        
        // Process input (file or directory)
        if is_directory {
            process_directory_core(input_path_obj, &mut tar_builder, &progress_callback)?;
        } else {
            process_file_core(input_path_obj, &mut tar_builder, &progress_callback)?;
        }
        
        // Finalize the pipeline: TAR → Compression → Encryption → Output
        let compression_writer = tar_builder.into_inner().context("Failed to finish TAR archive")?;
        let encryption_writer = compression_writer.finalize()?;
        let (mut final_output, _hmac_bytes) = encryption_writer.finalize()?;
        final_output.flush().context("Failed to flush output file")?;
    } else {
        let mut tar_builder = Builder::new(encryption_writer);
        
        // Process input (file or directory)
        if is_directory {
            process_directory_core(input_path_obj, &mut tar_builder, &progress_callback)?;
        } else {
            process_file_core(input_path_obj, &mut tar_builder, &progress_callback)?;
        }
        
        // Finalize the pipeline: TAR → Encryption → Output
        let encryption_writer = tar_builder.into_inner().context("Failed to finish TAR archive")?;
        let (mut final_output, _hmac_bytes) = encryption_writer.finalize()?;
        final_output.flush().context("Failed to flush output file")?;
    }

    progress_callback(EncryptProgress::EncryptionComplete);
    
    if is_directory {
        log_callback(&format!("Directory encrypted successfully: {}", output_path));
    } else {
        log_callback(&format!("File encrypted successfully: {}", output_path));
    }
    Ok(())
}

/// Core decryption function without UI dependencies
pub fn decrypt_core<P, L>(
    input_path: &str,
    output_path: &str,
    password: &str,
    progress_callback: &P,
    log_callback: &L,
) -> Result<()>
where
    P: Fn(DecryptProgress),
    L: Fn(&str),
{
    // Open encrypted file and buffer for streaming
    let file = File::open(input_path)
        .with_context(|| format!("Failed to open encrypted file: {}", input_path))?;
    let mut reader = BufReader::with_capacity(STREAM_BUFFER_SIZE, file);

    // Read CBOR header length (first 4 bytes)
    let mut header_length_bytes = [0u8; 4];
    reader.read_exact(&mut header_length_bytes)
        .with_context(|| format!("Failed to read CBOR header length from: {}", input_path))?;
    let header_length = u32::from_le_bytes(header_length_bytes) as usize;

    // Validate header length
    if header_length == 0 {
        bail!("Invalid CBOR header: header length is zero");
    }
    if header_length > MAX_HEADER_SIZE {
        bail!("CBOR header too large: {} bytes (maximum: {})", header_length, MAX_HEADER_SIZE);
    }

    // Read CBOR header data
    let mut cbor_header_data = vec![0u8; header_length];
    reader.read_exact(&mut cbor_header_data)
        .with_context(|| "Failed to read CBOR header data")?;

    // Deserialize and validate header
    let header = deserialize_header_from_cbor(&cbor_header_data)?;
    validate_header(&header)?;
    
    // Parse the encryption algorithm from header
    let algorithm = EncryptionAlgorithm::from_string(&header.encryption_algorithm)?;
    
    // Extract Argon2 parameters from header
    let argon2_params = Argon2Params::new(
        header.kdf.memory_cost / 1024, // Convert KB back to MB
        header.kdf.time_cost,
        header.kdf.parallelism,
    )?;
    
    // Derive decryption key from password and salt from header
    let key = derive_key_with_callback(password, &header.salt, &argon2_params, log_callback)?;
    
    // Get file size to calculate ciphertext size
    let file_metadata = std::fs::metadata(input_path)
        .with_context(|| format!("Failed to get file metadata: {}", input_path))?;
    let total_file_size = file_metadata.len();
    let ciphertext_size = total_file_size - 4 - header_length as u64; // Subtract header length and header data
    
    // Create encryption info for progress callback
    let encryption_info = EncryptionInfo {
        version: header.version,
        algorithm: header.encryption_algorithm.clone(),
        compression: header.compression.as_ref().map(|c| format!("{} (level {})", c.algorithm, c.level)),
        kdf_info: format!("{} ({}MB, {} iterations, {} threads)", 
                         header.kdf.algorithm, 
                         header.kdf.memory_cost / 1024,
                         header.kdf.time_cost,
                         header.kdf.parallelism),
        chunk_size: header.chunk_size,
    };
    
    // Report decryption start
    progress_callback(DecryptProgress::DecryptionStarted { 
        encryption_info,
        total_bytes: ciphertext_size,
    });
    
    // Create streaming decryption reader
    let decryption_reader = StreamingDecryptionReader::new(
        reader,
        algorithm.clone(),
        key,
        header.nonce.clone(),
        &header.salt,
        ciphertext_size,
    )?;
    
    // Create progress-aware reader wrapper - pass reference to callback
    let progress_reader = ProgressAwareReader::new(decryption_reader, ciphertext_size, &progress_callback);
    
    // Create decompression reader if needed
    let decompressed_reader: Box<dyn Read> = if let Some(ref compression) = header.compression {
        let compression_alg = CompressionAlgorithm::from_string(&compression.algorithm)?;
        match compression_alg {
            CompressionAlgorithm::None => Box::new(progress_reader),
            CompressionAlgorithm::Zstd => {
                log_callback("Setting up streaming decompression with zstd...");
                Box::new(zstd::Decoder::new(progress_reader)
                    .context("Failed to create zstd decoder")?)
            }
        }
    } else {
        Box::new(progress_reader)
    };
    
    // Create TAR archive from the streaming reader and extract directly
    log_callback("Setting up streaming TAR extraction...");
    let mut tar_archive = tar::Archive::new(decompressed_reader);
    
    // Check if output already exists
    if Path::new(output_path).exists() {
        bail!("Output path already exists: {}", output_path);
    }
    
    // Get TAR entries to determine extraction strategy
    let entries = tar_archive.entries()
        .context("Failed to read TAR entries")?;
    
    // Collect first few entries to determine if it's a single file
    let mut entry_count = 0;
    
    for entry in entries {
        let _entry = entry.context("Failed to read TAR entry")?;
        entry_count += 1;
        
        // If we have more than 1 entry, treat as directory
        if entry_count > 1 {
            break;
        }
    }
    
    // We need to create a new reader since we consumed the first one
    let file2 = File::open(input_path)
        .with_context(|| format!("Failed to reopen encrypted file: {}", input_path))?;
    let mut reader2 = BufReader::with_capacity(STREAM_BUFFER_SIZE, file2);
    
    // Skip header again
    reader2.read_exact(&mut [0u8; 4])?; // header length
    let mut cbor_skip = vec![0u8; header_length];
    reader2.read_exact(&mut cbor_skip)?;
    
    let decryption_reader2 = StreamingDecryptionReader::new(
        reader2,
        algorithm,
        key,
        header.nonce.clone(),
        &header.salt,
        ciphertext_size,
    )?;
    
    // Wrap the second reader with progress tracking since this is where the actual work happens
    let progress_reader2 = ProgressAwareReader::new(decryption_reader2, ciphertext_size, &progress_callback);
    
    let final_reader: Box<dyn Read> = if let Some(ref compression) = header.compression {
        let compression_alg = CompressionAlgorithm::from_string(&compression.algorithm)?;
        match compression_alg {
            CompressionAlgorithm::None => Box::new(progress_reader2),
            CompressionAlgorithm::Zstd => {
                Box::new(zstd::Decoder::new(progress_reader2)
                    .context("Failed to create zstd decoder")?)
            }
        }
    } else {
        Box::new(progress_reader2)
    };
    
    let mut tar_archive2 = tar::Archive::new(final_reader);
    
    // Report extraction strategy
    let progress_callback_ref = &progress_callback;
    progress_callback_ref(DecryptProgress::ExtractionStrategy {
        is_single_file: entry_count == 1,
        output_path: output_path.to_string(),
    });
    
    if entry_count == 1 {
        // Single file in TAR - extract to the output path directly
        let mut entries = tar_archive2.entries()?;
        if let Some(entry) = entries.next() {
            let mut entry = entry.context("Failed to read TAR entry")?;
            let mut output_file = File::create(output_path)
                .with_context(|| format!("Failed to create output file: {}", output_path))?;
            
            std::io::copy(&mut entry, &mut output_file)
                .context("Failed to extract file from TAR")?;
            
            log_callback(&format!("File extracted successfully: {}", output_path));
        } else {
            bail!("TAR archive is empty");
        }
    } else {
        // Multiple files/directories - extract to directory
        fs::create_dir_all(output_path)
            .with_context(|| format!("Failed to create output directory: {}", output_path))?;
        
        tar_archive2.unpack(output_path)
            .with_context(|| format!("Failed to extract TAR archive to: {}", output_path))?;
        
        log_callback(&format!("Directory decrypted and extracted successfully: {}", output_path));
    }
    
    // Verify HMAC for file integrity after extraction is complete
    progress_callback(DecryptProgress::VerifyingIntegrity);
    
    // Read HMAC from the end of the original file
    let mut hmac_file = File::open(input_path)
        .with_context(|| format!("Failed to reopen file for HMAC verification: {}", input_path))?;
    
    // Seek to HMAC position (last 32 bytes)
    hmac_file.seek(std::io::SeekFrom::End(-(HMAC_SIZE as i64)))
        .context("Failed to seek to HMAC position")?;
    
    let mut stored_hmac = vec![0u8; HMAC_SIZE];
    hmac_file.read_exact(&mut stored_hmac)
        .context("Failed to read stored HMAC")?;
    
    // Compute expected HMAC by re-reading and decrypting the entire file
    let verification_file = File::open(input_path)
        .with_context(|| format!("Failed to open file for HMAC verification: {}", input_path))?;
    let mut verification_reader = BufReader::with_capacity(STREAM_BUFFER_SIZE, verification_file);
    
    // Skip header
    verification_reader.read_exact(&mut [0u8; 4])?; // header length
    let mut cbor_skip = vec![0u8; header_length];
    verification_reader.read_exact(&mut cbor_skip)?;
    
    // Create decryption reader for HMAC verification
    let verification_algorithm = EncryptionAlgorithm::from_string(&header.encryption_algorithm)?;
    let mut hmac_verification_reader = StreamingDecryptionReader::new(
        verification_reader,
        verification_algorithm,
        key,
        header.nonce,
        &header.salt,
        ciphertext_size,
    )?;
    
    // Read all plaintext to build HMAC (this is memory-efficient as it streams)
    let mut temp_buffer = vec![0u8; 64 * 1024]; // 64KB buffer
    loop {
        match hmac_verification_reader.read(&mut temp_buffer) {
            Ok(0) => break, // EOF
            Ok(_) => continue, // Keep reading to build HMAC
            Err(e) => return Err(anyhow::anyhow!("Failed to read for HMAC verification: {}", e)),
        }
    }
    
    // Now verify the HMAC
    if !hmac_verification_reader.verify_hmac(&stored_hmac)? {
        bail!("File integrity verification failed - file may be corrupted or tampered with");
    }
    
    log_callback("File integrity verified successfully");
    progress_callback(DecryptProgress::DecryptionComplete);
    Ok(())
}

/// Progress-aware reader wrapper that reports bytes read
struct ProgressAwareReader<'a, R: Read> {
    inner: R,
    bytes_read: u64,
    total_bytes: u64,
    progress_callback: &'a dyn Fn(DecryptProgress),
}

impl<'a, R: Read> ProgressAwareReader<'a, R> {
    fn new(inner: R, total_bytes: u64, progress_callback: &'a dyn Fn(DecryptProgress)) -> Self {
        Self {
            inner,
            bytes_read: 0,
            total_bytes,
            progress_callback,
        }
    }
}

impl<'a, R: Read> Read for ProgressAwareReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.inner.read(buf)?;
        self.bytes_read += bytes_read as u64;
        (self.progress_callback)(DecryptProgress::BytesProcessed {
            current: self.bytes_read,
            total: self.total_bytes,
        });
        Ok(bytes_read)
    }
}

/// Helper functions without UI dependencies
fn process_directory_core<W: Write, P>(
    input_path: &Path,
    tar_builder: &mut Builder<W>,
    progress_callback: P,
) -> Result<()>
where
    P: Fn(EncryptProgress),
{
    progress_callback(EncryptProgress::CountingFiles);
    let total_files = count_files_in_directory_core(input_path)?;
    progress_callback(EncryptProgress::FileCountComplete { total_files });
    
    let mut processed_files = 0;
    stream_tar_directory_recursive_core(
        input_path,
        input_path,
        tar_builder,
        &mut processed_files,
        &progress_callback,
    )?;
    Ok(())
}

fn process_file_core<W: Write, P>(
    input_path: &Path,
    tar_builder: &mut Builder<W>,
    progress_callback: P,
) -> Result<()>
where
    P: Fn(EncryptProgress),
{
    let file_name = input_path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid file name"))?;
    
    progress_callback(EncryptProgress::ProcessingFile { 
        current: 1, 
        total: 1, 
        name: file_name.to_string() 
    });
    
    let mut file = File::open(input_path)
        .with_context(|| format!("Failed to open file: {:?}", input_path))?;
    tar_builder.append_file(file_name, &mut file)
        .with_context(|| format!("Failed to add file to tar: {}", file_name))?;
    Ok(())
}

/// Count files in directory recursively for progress tracking
fn count_files_in_directory_core(dir_path: &Path) -> Result<u64> {
    let mut count = 0;
    let entries = fs::read_dir(dir_path)
        .with_context(|| format!("Failed to read directory: {}", dir_path.display()))?;
    
    for entry in entries {
        let entry = entry.context("Failed to read directory entry")?;
        let path = entry.path();
        
        if path.is_dir() {
            count += 1; // Count the directory itself
            count += count_files_in_directory_core(&path)?; // Recursively count contents
        } else {
            count += 1; // Count the file
        }
    }
    
    Ok(count)
}

/// Recursively add directory contents to streaming TAR builder
fn stream_tar_directory_recursive_core<W: Write>(
    base_path: &Path,
    current_path: &Path,
    tar: &mut Builder<W>,
    processed_files: &mut u64,
    progress_callback: &dyn Fn(EncryptProgress),
) -> Result<()>
{
    let entries = fs::read_dir(current_path)
        .with_context(|| format!("Failed to read directory: {}", current_path.display()))?;
    
    for entry in entries {
        let entry = entry.context("Failed to read directory entry")?;
        let path = entry.path();
        let relative_path = path.strip_prefix(base_path)
            .context("Failed to create relative path")?;
        
        if path.is_dir() {
            // Add directory to TAR
            tar.append_dir(relative_path, &path)
                .with_context(|| format!("Failed to add directory to tar: {}", relative_path.display()))?;
            
            // Update progress
            *processed_files += 1;
            progress_callback(EncryptProgress::ProcessingFile { 
                current: *processed_files, 
                total: 0, // We'll update this when we know the total
                name: relative_path.display().to_string() 
            });
            
            // Recursively add directory contents
            stream_tar_directory_recursive_core(base_path, &path, tar, processed_files, &progress_callback)?;
        } else {
            // Add file to TAR with streaming
            let mut file = File::open(&path)
                .with_context(|| format!("Failed to open file: {}", path.display()))?;
            
            tar.append_file(relative_path, &mut file)
                .with_context(|| format!("Failed to add file to tar: {}", relative_path.display()))?;
            
            // Update progress
            *processed_files += 1;
            progress_callback(EncryptProgress::ProcessingFile { 
                current: *processed_files, 
                total: 0, // We'll update this when we know the total
                name: relative_path.display().to_string() 
            });
        }
    }
    
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    
    const TEST_PASSWORD: &str = "TestPassword123!";
    const TEST_DATA: &[u8] = b"Hello, core world! This is test data for core encryption.";
    
    fn create_test_argon2_params() -> Argon2Params {
        // Fast parameters for testing
        Argon2Params::new(8, 1, 1).unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_core_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test_input.txt");
        let encrypted_file = temp_dir.path().join("test_output.sec");
        let decrypted_file = temp_dir.path().join("test_decrypted.txt");
        
        // Create test input file
        fs::write(&input_file, TEST_DATA).unwrap();
        
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let params = create_test_argon2_params();
        
        // Encrypt the file
        encrypt_core(
            input_file.to_str().unwrap(),
            encrypted_file.to_str().unwrap(),
            TEST_PASSWORD,
            &algorithm,
            &params,
            None,
            &|_| {}, // No progress tracking in test
            &|_| {}, // No logging in test
        ).unwrap();
        
        // Decrypt the file
        decrypt_core(
            encrypted_file.to_str().unwrap(),
            decrypted_file.to_str().unwrap(),
            TEST_PASSWORD,
            &|_| {}, // No progress tracking in test
            &|_| {}, // No logging in test
        ).unwrap();
        
        // Verify decrypted file matches original
        let decrypted_data = fs::read(&decrypted_file).unwrap();
        assert_eq!(decrypted_data, TEST_DATA);
    }
}
