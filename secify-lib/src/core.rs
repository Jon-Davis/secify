//! Core streaming encryption/decryption functionality without UI dependencies
//! 
//! This module provides the pure business logic for creating and reading .sec files,
//! separated from progress reporting and console output.

use std::fs::{self, File};
use std::path::Path;
use std::io::{Read, Write, BufReader, BufWriter, Seek};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zstd;

use crate::crypto::*;
use crate::error::{SecifyError, Result};

/// Size of the read buffer for streaming operations
const STREAM_BUFFER_SIZE: usize = 64 * 1024; // 64KB

/// Maximum allowed protobuf header size (1MB)
const MAX_HEADER_SIZE: usize = 1_048_576;

/// HMAC size in bytes (SHA256)
const HMAC_SIZE: usize = 32;

/// Custom archive format for minimal overhead
/// Format: [name_len: u32][name: utf8][size: u64][data]
struct MinimalArchiveWriter<W: Write> {
    writer: W,
}

impl<W: Write> MinimalArchiveWriter<W> {
    fn new(writer: W) -> Self {
        Self { writer }
    }
    
    fn add_file(&mut self, path: &str, size: u64, mut reader: impl Read) -> std::io::Result<()> {
        // Write name length and name
        let name_bytes = path.as_bytes();
        self.writer.write_all(&(name_bytes.len() as u32).to_le_bytes())?;
        self.writer.write_all(name_bytes)?;
        
        // Write file size
        self.writer.write_all(&size.to_le_bytes())?;
        
        // Copy file data
        std::io::copy(&mut reader, &mut self.writer)?;
        
        Ok(())
    }
    
    fn finish(self) -> W {
        self.writer
    }
}

struct MinimalArchiveReader<R: Read> {
    reader: R,
}

impl<R: Read> MinimalArchiveReader<R> {
    fn new(reader: R) -> Self {
        Self { reader }
    }
    
    fn next_entry(&mut self) -> std::io::Result<Option<(String, u64)>> {
        // Try to read name length
        let mut name_len_bytes = [0u8; 4];
        match self.reader.read_exact(&mut name_len_bytes) {
            Ok(()) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        
        let name_len = u32::from_le_bytes(name_len_bytes) as usize;
        if name_len > 4096 { // Sanity check
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Name too long"));
        }
        
        // Read name
        let mut name_bytes = vec![0u8; name_len];
        self.reader.read_exact(&mut name_bytes)?;
        let name = String::from_utf8(name_bytes)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-8 in filename"))?;
        
        // Read file size
        let mut size_bytes = [0u8; 8];
        self.reader.read_exact(&mut size_bytes)?;
        let size = u64::from_le_bytes(size_bytes);
        
        Ok(Some((name, size)))
    }
    
    fn read_file_data(&mut self, size: u64, mut writer: impl Write) -> std::io::Result<()> {
        let mut remaining = size;
        let mut buffer = vec![0u8; 64 * 1024]; // 64KB buffer
        
        while remaining > 0 {
            let to_read = std::cmp::min(buffer.len() as u64, remaining) as usize;
            let bytes_read = self.reader.read(&mut buffer[..to_read])?;
            if bytes_read == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Unexpected end of archive"));
            }
            
            writer.write_all(&buffer[..bytes_read])?;
            remaining -= bytes_read as u64;
        }
        
        Ok(())
    }
}

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
            .map_err(|e| SecifyError::crypto(format!("Failed to create HMAC: {}", e)))?;
        
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

        // Only write HMAC if more than one chunk was encrypted
        // Single chunk files rely on AEAD authentication only
        if self.chunk_counter > 1 {
            // Get final HMAC
            let hmac_result = self.hmac.finalize();
            let hmac_bytes = hmac_result.into_bytes().to_vec();
            
            // Write HMAC to the end
            self.inner.write_all(&hmac_bytes)?;
            
            Ok((self.inner, hmac_bytes))
        } else {
            // No HMAC for single chunk - return empty HMAC bytes to indicate this
            Ok((self.inner, Vec::new()))
        }
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
        
        // Don't subtract HMAC size initially - we'll determine if it exists during reading
        // based on whether we have multiple chunks
        
        // Create HMAC for integrity
        let mut hmac_key = Vec::with_capacity(KEY_LENGTH + salt.len());
        hmac_key.extend_from_slice(&key);
        hmac_key.extend_from_slice(salt);
        let hmac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key)
            .map_err(|e| SecifyError::crypto(format!("Failed to create HMAC: {}", e)))?;

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
            file_size,
            finished: false,
        })
    }
    
    fn decrypt_next_chunk(&mut self) -> Result<bool> {
        if self.finished {
            return Ok(false);
        }
        
        // For first chunk, read normally
        // For subsequent chunks, we know it's multi-chunk so reserve HMAC space
        let effective_file_size = if self.chunk_counter == 0 {
            self.file_size
        } else {
            // Multi-chunk file - leave space for HMAC
            self.file_size.saturating_sub(HMAC_SIZE as u64)
        };
        
        if self.total_read >= effective_file_size {
            return Ok(false);
        }
        
        // Read next encrypted chunk
        let remaining_data = effective_file_size - self.total_read;
        let bytes_to_read = remaining_data.min(self.chunk_size as u64) as usize;
        
        if bytes_to_read == 0 {
            self.finished = true;
            return Ok(false);
        }
        
        let mut encrypted_chunk = vec![0u8; bytes_to_read];
        
        let mut bytes_read = 0;
        while bytes_read < bytes_to_read {
            match self.inner.read(&mut encrypted_chunk[bytes_read..]) {
                Ok(0) => break, // EOF
                Ok(n) => bytes_read += n,
                Err(e) => return Err(SecifyError::Io(e)),
            }
        }
        
        if bytes_read == 0 {
            self.finished = true;
            return Ok(false);
        }
        
        encrypted_chunk.truncate(bytes_read);
        self.total_read += bytes_read as u64;
        
        // After reading first chunk, check if there's significantly more data
        // If so, this is a multi-chunk file and we should reserve HMAC space for future reads
        if self.chunk_counter == 0 && self.total_read < self.file_size.saturating_sub(HMAC_SIZE as u64) {
            // There's more data after this chunk, so this is multi-chunk
            // No need to do anything special, subsequent reads will handle HMAC reservation
        }
        
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
        // If only one chunk was processed, no HMAC verification is needed
        // Single chunk files rely solely on AEAD authentication
        if self.chunk_counter <= 1 {
            return Ok(true); // Always pass verification for single chunk files
        }
        
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
                    Err(e) => return Err(SecifyError::Io(e)),
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
                Err(e) => return Err(SecifyError::Io(e)),
            }
        }
        
        if hmac_bytes_read != HMAC_SIZE {
            return Err(SecifyError::authentication(format!("Incomplete HMAC read: expected {} bytes, got {}", HMAC_SIZE, hmac_bytes_read)));
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
        return Err(SecifyError::file_error(format!("Input path does not exist: {}", input_path)));
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

    // Create header - only use minimal archive format for directories
    let archive_format = if is_directory { Some("minimal".to_string()) } else { None };
    let header = create_encryption_header(&salt, &base_nonce, algorithm, argon2_params, DEFAULT_CHUNK_SIZE as u32, compression.clone(), archive_format);
    let protobuf_header = serialize_header_to_protobuf(&header)?;

    // Create output file
    let output_file = File::create(output_path)
        .map_err(|e| SecifyError::file_error(format!("Failed to create output file {}: {}", output_path, e)))?;
    let mut buffered_output = BufWriter::with_capacity(STREAM_BUFFER_SIZE, output_file);

    // Write header length and header
    buffered_output.write_all(&(protobuf_header.len() as u32).to_le_bytes())?;
    buffered_output.write_all(&protobuf_header)?;

    // Create streaming encryption wrapper
    let mut encryption_writer = StreamingEncryptionWriter::new(
        buffered_output,
        algorithm.clone(),
        key,
        base_nonce,
        &salt,
    )?;

    progress_callback(EncryptProgress::EncryptionStarted);

    // Handle encryption based on whether we need archive format or not
    if header.archive.is_some() {
        // Directory: Use minimal archive format with compression pipeline
        if compression.is_some() {
            let compression_writer = CompressionBufferingWriter::new(encryption_writer, compression.as_ref())?;
            let mut archive_builder = MinimalArchiveWriter::new(compression_writer);
            
            // Process directory
            process_directory_minimal(input_path_obj, &mut archive_builder, &progress_callback)?;
            
            // Finalize the pipeline: MinimalArchive → Compression → Encryption → Output
            let compression_writer = archive_builder.finish();
            let encryption_writer = compression_writer.finalize()?;
            let (mut final_output, _hmac_bytes) = encryption_writer.finalize()?;
            final_output.flush().map_err(|e| SecifyError::Io(e))?;
        } else {
            let mut archive_builder = MinimalArchiveWriter::new(encryption_writer);
            
            // Process directory
            process_directory_minimal(input_path_obj, &mut archive_builder, &progress_callback)?;
            
            // Finalize the pipeline: MinimalArchive → Encryption → Output
            let encryption_writer = archive_builder.finish();
            let (mut final_output, _hmac_bytes) = encryption_writer.finalize()?;
            final_output.flush().map_err(|e| SecifyError::Io(e))?;
        }
    } else {
        // Single file: Direct streaming without archive overhead
        if compression.is_some() {
            let mut compression_writer = CompressionBufferingWriter::new(encryption_writer, compression.as_ref())?;
            
            // Stream file content directly to compression then encryption
            let mut file = File::open(input_path_obj)
                .map_err(|e| SecifyError::file_error(format!("Failed to open file {:?}: {}", input_path_obj, e)))?;
            
            progress_callback(EncryptProgress::ProcessingFile { 
                current: 1, 
                total: 1, 
                name: input_path_obj.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("unknown").to_string()
            });
            
            std::io::copy(&mut file, &mut compression_writer)?;
            
            // Finalize the pipeline: Compression → Encryption → Output
            let encryption_writer = compression_writer.finalize()?;
            let (mut final_output, _hmac_bytes) = encryption_writer.finalize()?;
            final_output.flush().map_err(|e| SecifyError::Io(e))?;
        } else {
            // Direct file streaming to encryption
            let mut file = File::open(input_path_obj)
                .map_err(|e| SecifyError::file_error(format!("Failed to open file {:?}: {}", input_path_obj, e)))?;
            
            progress_callback(EncryptProgress::ProcessingFile { 
                current: 1, 
                total: 1, 
                name: input_path_obj.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("unknown").to_string()
            });
            
            std::io::copy(&mut file, &mut encryption_writer)?;
            
            // Finalize encryption
            let (mut final_output, _hmac_bytes) = encryption_writer.finalize()?;
            final_output.flush().map_err(|e| SecifyError::Io(e))?;
        }
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
        .map_err(|e| SecifyError::file_error(format!("Failed to open encrypted file {}: {}", input_path, e)))?;
    let mut reader = BufReader::with_capacity(STREAM_BUFFER_SIZE, file);

    // Read protobuf header length (first 4 bytes)
    let mut header_length_bytes = [0u8; 4];
    reader.read_exact(&mut header_length_bytes)
        .map_err(|e| SecifyError::invalid_format(format!("Failed to read protobuf header length from {}: {}", input_path, e)))?;
    let header_length = u32::from_le_bytes(header_length_bytes) as usize;

    // Validate header length
    if header_length == 0 {
        return Err(SecifyError::invalid_format("Invalid protobuf header: header length is zero"));
    }
    if header_length > MAX_HEADER_SIZE {
        return Err(SecifyError::invalid_format(format!("Protobuf header too large: {} bytes (maximum: {})", header_length, MAX_HEADER_SIZE)));
    }

    // Read protobuf header data
    let mut protobuf_header_data = vec![0u8; header_length];
    reader.read_exact(&mut protobuf_header_data)
        .map_err(|e| SecifyError::invalid_format(format!("Failed to read protobuf header data: {}", e)))?;

    // Deserialize and validate header
    let header = deserialize_header_from_protobuf(&protobuf_header_data)?;
    validate_header(&header)?;
    
    // Parse the encryption algorithm from header
    let algorithm = EncryptionAlgorithm::from_string(&header.encryption_algorithm)?;
    
    // Extract Argon2 parameters from header
    let kdf = header.kdf.as_ref().ok_or_else(|| SecifyError::invalid_format("Missing KDF configuration"))?;
    let argon2_params = Argon2Params::new(
        kdf.memory_cost / 1024, // Convert KB back to MB
        kdf.time_cost,
        kdf.parallelism,
    )?;
    
    // Derive decryption key from password and salt from header
    let key = derive_key_with_callback(password, &header.salt, &argon2_params, log_callback)?;
    
    // Get file size to calculate ciphertext size
    let file_metadata = std::fs::metadata(input_path)
        .map_err(|e| SecifyError::file_error(format!("Failed to get file metadata for {}: {}", input_path, e)))?;
    let total_file_size = file_metadata.len();
    
    // For now, assume worst case (HMAC present) for initial size calculation
    // We'll adjust during verification based on actual chunk count
    let ciphertext_size = total_file_size - 4 - header_length as u64; // Subtract header length and header data
    
    // Create encryption info for progress callback
    let encryption_info = EncryptionInfo {
        version: header.version,
        algorithm: header.encryption_algorithm.clone(),
        compression: header.compression.as_ref().map(|c| format!("{} (level {})", c.algorithm, c.level)),
        kdf_info: format!("{} ({}MB, {} iterations, {} threads)", 
                         kdf.algorithm, 
                         kdf.memory_cost / 1024,
                         kdf.time_cost,
                         kdf.parallelism),
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
    let mut decompressed_reader: Box<dyn Read> = if let Some(ref compression) = header.compression {
        let compression_alg = CompressionAlgorithm::from_string(&compression.algorithm)?;
        match compression_alg {
            CompressionAlgorithm::None => Box::new(progress_reader),
            CompressionAlgorithm::Zstd => {
                log_callback("Setting up streaming decompression with zstd...");
                Box::new(zstd::Decoder::new(progress_reader)
                    .map_err(|e| SecifyError::decompression(format!("Failed to create zstd decoder: {}", e)))?)
            }
        }
    } else {
        Box::new(progress_reader)
    };
    
    // Check if output already exists
    if Path::new(output_path).exists() {
        return Err(SecifyError::file_error(format!("Output path already exists: {}", output_path)));
    }

    // Handle extraction based on archive format
    if let Some(ref archive_format) = header.archive {
        if archive_format == "minimal" {
            // Minimal archive format (directory)
            log_callback("Setting up streaming minimal archive extraction...");
            
            // Report extraction strategy as directory
            progress_callback(DecryptProgress::ExtractionStrategy {
                is_single_file: false,
                output_path: output_path.to_string(),
            });
            
            // Create output directory
            fs::create_dir_all(output_path)
                .map_err(|e| SecifyError::file_error(format!("Failed to create output directory {}: {}", output_path, e)))?;
            
            // Extract minimal archive
            let mut archive_reader = MinimalArchiveReader::new(decompressed_reader);
            while let Some((name, size)) = archive_reader.next_entry()
                .map_err(|e| SecifyError::archive(format!("Failed to read archive entry: {}", e)))? {
                
                let output_file_path = Path::new(output_path).join(&name);
                
                if name.ends_with('/') {
                    // Directory entry
                    fs::create_dir_all(&output_file_path)
                        .map_err(|e| SecifyError::file_error(format!("Failed to create directory {}: {}", output_file_path.display(), e)))?;
                } else {
                    // File entry
                    // Ensure parent directory exists
                    if let Some(parent) = output_file_path.parent() {
                        fs::create_dir_all(parent)
                            .map_err(|e| SecifyError::file_error(format!("Failed to create parent directory {}: {}", parent.display(), e)))?;
                    }
                    
                    let mut output_file = File::create(&output_file_path)
                        .map_err(|e| SecifyError::file_error(format!("Failed to create output file {}: {}", output_file_path.display(), e)))?;
                    
                    archive_reader.read_file_data(size, &mut output_file)
                        .map_err(|e| SecifyError::archive(format!("Failed to extract file data for {}: {}", name, e)))?;
                }
            }
            
            log_callback(&format!("Directory decrypted and extracted successfully: {}", output_path));
        } else {
            return Err(SecifyError::invalid_format(format!("Unsupported archive format: {}", archive_format)));
        }
    } else {
        // Single file format (no archive)
        // Report extraction strategy as single file
        progress_callback(DecryptProgress::ExtractionStrategy {
            is_single_file: true,
            output_path: output_path.to_string(),
        });
        
        // Stream directly to output file
        let mut output_file = File::create(output_path)
            .map_err(|e| SecifyError::file_error(format!("Failed to create output file {}: {}", output_path, e)))?;
        
        std::io::copy(&mut decompressed_reader, &mut output_file)
            .map_err(|e| SecifyError::file_error(format!("Failed to write decrypted data: {}", e)))?;
        
        log_callback(&format!("File decrypted successfully: {}", output_path));
    }
    
    // Verify HMAC for file integrity after extraction is complete
    progress_callback(DecryptProgress::VerifyingIntegrity);
    
    // Create a new decryption reader to check if this is a single-chunk file
    // We'll use this to determine if HMAC verification is needed
    let verification_file = File::open(input_path)
        .map_err(|e| SecifyError::file_error(format!("Failed to open file for HMAC verification {}: {}", input_path, e)))?;
    let mut verification_reader = BufReader::with_capacity(STREAM_BUFFER_SIZE, verification_file);
    
    // Skip header
    verification_reader.read_exact(&mut [0u8; 4])?; // header length
    let mut protobuf_skip = vec![0u8; header_length];
    verification_reader.read_exact(&mut protobuf_skip)?;
    
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
    
    // Read all plaintext to build HMAC and count chunks
    let mut temp_buffer = vec![0u8; 64 * 1024]; // 64KB buffer
    loop {
        match hmac_verification_reader.read(&mut temp_buffer) {
            Ok(0) => break, // EOF
            Ok(_) => continue, // Keep reading to build HMAC
            Err(e) => return Err(SecifyError::Io(e)),
        }
    }
    
    // Check if this was a single chunk file
    if hmac_verification_reader.chunk_counter <= 1 {
        // Single chunk file - no HMAC verification needed
        log_callback("Single chunk file detected - HMAC verification skipped (AEAD provides sufficient integrity)");
    } else {
        // Multi-chunk file - verify HMAC
        // Read HMAC from the end of the original file
        let mut hmac_file = File::open(input_path)
            .map_err(|e| SecifyError::file_error(format!("Failed to reopen file for HMAC verification {}: {}", input_path, e)))?;
        
        // Seek to HMAC position (last 32 bytes)
        hmac_file.seek(std::io::SeekFrom::End(-(HMAC_SIZE as i64)))
            .map_err(|e| SecifyError::Io(e))?;
        
        let mut stored_hmac = vec![0u8; HMAC_SIZE];
        hmac_file.read_exact(&mut stored_hmac)
            .map_err(|e| SecifyError::authentication(format!("Failed to read stored HMAC: {}", e)))?;
        
        // Verify the HMAC
        if !hmac_verification_reader.verify_hmac(&stored_hmac)? {
            return Err(SecifyError::authentication("File integrity verification failed - file may be corrupted or tampered with"));
        }
        
        log_callback("Multi-chunk file HMAC verified successfully");
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
fn process_directory_minimal<W: Write, P>(
    input_path: &Path,
    archive_builder: &mut MinimalArchiveWriter<W>,
    progress_callback: P,
) -> Result<()>
where
    P: Fn(EncryptProgress),
{
    progress_callback(EncryptProgress::CountingFiles);
    let total_files = count_files_in_directory_core(input_path)?;
    progress_callback(EncryptProgress::FileCountComplete { total_files });
    
    let mut processed_files = 0;
    stream_minimal_directory_recursive(
        input_path,
        input_path,
        archive_builder,
        &mut processed_files,
        &progress_callback,
    )?;
    Ok(())
}

/// Count files in directory recursively for progress tracking
fn count_files_in_directory_core(dir_path: &Path) -> Result<u64> {
    let mut count = 0;
    let entries = fs::read_dir(dir_path)
        .map_err(|e| SecifyError::file_error(format!("Failed to read directory {}: {}", dir_path.display(), e)))?;
    
    for entry in entries {
        let entry = entry.map_err(|e| SecifyError::file_error(format!("Failed to read directory entry: {}", e)))?;
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

/// Recursively add directory contents to minimal archive builder
fn stream_minimal_directory_recursive<W: Write>(
    base_path: &Path,
    current_path: &Path,
    archive: &mut MinimalArchiveWriter<W>,
    processed_files: &mut u64,
    progress_callback: &dyn Fn(EncryptProgress),
) -> Result<()>
{
    let entries = fs::read_dir(current_path)
        .map_err(|e| SecifyError::file_error(format!("Failed to read directory {}: {}", current_path.display(), e)))?;
    
    for entry in entries {
        let entry = entry.map_err(|e| SecifyError::file_error(format!("Failed to read directory entry: {}", e)))?;
        let path = entry.path();
        let relative_path = path.strip_prefix(base_path)
            .map_err(|e| SecifyError::file_error(format!("Failed to create relative path: {}", e)))?;
        
        if path.is_dir() {
            // For directories, add a special entry with "/" suffix and zero size
            let dir_name = format!("{}/", relative_path.display());
            archive.add_file(&dir_name, 0, std::io::empty())
                .map_err(|e| SecifyError::archive(format!("Failed to add directory to archive {}: {}", dir_name, e)))?;
            
            // Update progress
            *processed_files += 1;
            progress_callback(EncryptProgress::ProcessingFile { 
                current: *processed_files, 
                total: 0, // We'll update this when we know the total
                name: relative_path.display().to_string() 
            });
            
            // Recursively add directory contents
            stream_minimal_directory_recursive(base_path, &path, archive, processed_files, &progress_callback)?;
        } else {
            // Add file to archive with streaming
            let file = File::open(&path)
                .map_err(|e| SecifyError::file_error(format!("Failed to open file {}: {}", path.display(), e)))?;
            
            let metadata = file.metadata()
                .map_err(|e| SecifyError::file_error(format!("Failed to get file metadata {}: {}", path.display(), e)))?;
            let file_size = metadata.len();
            
            archive.add_file(&relative_path.display().to_string(), file_size, file)
                .map_err(|e| SecifyError::archive(format!("Failed to add file to archive {}: {}", relative_path.display(), e)))?;
            
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
                return Err(SecifyError::invalid_config(format!("Base nonce for {}/ChaCha20 must be 8 bytes, got {}", 
                      algorithm.to_string(), base_nonce.len())));
            }
            chunk_nonce[..8].copy_from_slice(base_nonce);
            chunk_nonce[8..12].copy_from_slice(&(chunk_counter as u32).to_le_bytes());
        }
        EncryptionAlgorithm::XChaCha20Poly1305 => {
            if base_nonce.len() != 16 {
                return Err(SecifyError::invalid_config(format!("Base nonce for XChaCha20 must be 16 bytes, got {}", base_nonce.len())));
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
