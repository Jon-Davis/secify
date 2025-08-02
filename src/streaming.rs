use std::fs::{self, File};
use std::path::Path;
use std::io::{Read, Write, BufReader, BufWriter, Seek};
use anyhow::{Result, Context, bail};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tar::Builder;
use zstd;

use crate::crypto::*;
use crate::progress::*;
use crate::tar_operations::{count_files_in_directory, stream_tar_directory_recursive};

/// Size of the read buffer for streaming operations
const STREAM_BUFFER_SIZE: usize = 64 * 1024; // 64KB

/// Maximum allowed CBOR header size (1MB)
const MAX_HEADER_SIZE: usize = 1_048_576;

/// HMAC size in bytes (SHA256)
const HMAC_SIZE: usize = 32;

/// A compression wrapper that handles TAR → Compress → Buffer → Encrypt pipeline
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

/// A streaming decryption reader that decrypts data as it's read
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

/// A progress-tracking wrapper for Read that updates a progress bar
pub struct ProgressTrackingReader<R: Read> {
    inner: R,
    progress_bar: indicatif::ProgressBar,
    bytes_read: u64,
}

impl<R: Read> ProgressTrackingReader<R> {
    pub fn new(inner: R, progress_bar: indicatif::ProgressBar) -> Self {
        Self {
            inner,
            progress_bar,
            bytes_read: 0,
        }
    }
    
    pub fn finish(self) -> R {
        // Don't finish the progress bar here - let the caller manage it
        self.inner
    }
}

impl<R: Read> Read for ProgressTrackingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.inner.read(buf)?;
        self.bytes_read += bytes_read as u64;
        self.progress_bar.set_position(self.bytes_read);
        Ok(bytes_read)
    }
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

/// Stream encrypt any file or directory using a full read → tar → compress → encrypt → write pipeline
/// This unified function handles both files and directories by putting them in a TAR archive
pub fn stream_encrypt_tar(
    input_path: &str,
    output_path: &str,
    password: &str,
    algorithm: &EncryptionAlgorithm,
    argon2_params: &Argon2Params,
) -> Result<()> {
    stream_encrypt_tar_with_compression(input_path, output_path, password, algorithm, argon2_params, None)
}

/// Helper function to process a directory for TAR archiving
fn process_directory(input_path: &Path, tar_builder: &mut Builder<impl Write>) -> Result<()> {
    println!("Counting files...");
    let total_files = count_files_in_directory(input_path)?;
    let progress_bar = create_standard_progress_bar(total_files, "Streaming TAR");
    let mut processed_files = 0;
    stream_tar_directory_recursive(
        input_path,
        input_path,
        tar_builder,
        &progress_bar,
        &mut processed_files
    )?;
    progress_bar.finish_with_message("Streaming directory encryption complete");
    Ok(())
}

/// Helper function to process a single file for TAR archiving
fn process_file(input_path: &Path, tar_builder: &mut Builder<impl Write>) -> Result<()> {
    println!("Adding file to TAR archive...");
    let file_name = input_path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid file name"))?;
    let mut file = File::open(input_path)
        .with_context(|| format!("Failed to open file: {:?}", input_path))?;
    tar_builder.append_file(file_name, &mut file)
        .with_context(|| format!("Failed to add file to tar: {}", file_name))?;
    println!("File added to TAR archive");
    Ok(())
}

/// Stream encrypt with optional compression support
pub fn stream_encrypt_tar_with_compression(
    input_path: &str,
    output_path: &str,
    password: &str,
    algorithm: &EncryptionAlgorithm,
    argon2_params: &Argon2Params,
    compression: Option<CompressionConfig>,
) -> Result<()> {
    let input_path_obj = Path::new(input_path);
    if !input_path_obj.exists() {
        bail!("Input path does not exist: {}", input_path);
    }
    let is_directory = input_path_obj.is_dir();

    // Print operation type
    match (is_directory, compression.is_some()) {
        (true, true) => println!("Streaming directory encryption with compression and full pipeline (TAR → Compress → Encrypt)..."),
        (true, false) => println!("Streaming directory encryption with full pipeline (TAR → Encrypt)..."),
        (false, true) => println!("Streaming file encryption with compression and TAR archive format..."),
        (false, false) => println!("Streaming file encryption with TAR archive format..."),
    }

    // Generate cryptographic parameters
    let mut salt = [0u8; SALT_LENGTH];
    generate_secure_random_bytes(&mut salt)?;
    let base_nonce = generate_base_nonce(algorithm)?;
    let key = derive_key(password, &salt, argon2_params)?;

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

    // Create writer chain based on compression setting
    if compression.is_some() {
        let compression_writer = CompressionBufferingWriter::new(encryption_writer, compression.as_ref())?;
        let mut tar_builder = Builder::new(compression_writer);
        
        // Process input (file or directory)
        if is_directory {
            process_directory(input_path_obj, &mut tar_builder)?;
        } else {
            process_file(input_path_obj, &mut tar_builder)?;
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
            process_directory(input_path_obj, &mut tar_builder)?;
        } else {
            process_file(input_path_obj, &mut tar_builder)?;
        }
        
        // Finalize the pipeline: TAR → Encryption → Output
        let encryption_writer = tar_builder.into_inner().context("Failed to finish TAR archive")?;
        let (mut final_output, _hmac_bytes) = encryption_writer.finalize()?;
        final_output.flush().context("Failed to flush output file")?;
    }

    if is_directory {
        println!("Directory encrypted successfully: {}", output_path);
    } else {
        println!("File encrypted successfully: {}", output_path);
    }
    Ok(())
}

/// Helper function to display decryption info from header
fn display_decryption_info(header: &crate::crypto::EncryptionHeader) {
    println!("File format version: {}", header.version);
    println!("Encryption: {}", header.encryption_algorithm);
    
    if let Some(ref compression) = header.compression {
        println!("Compression: {} (level {})", compression.algorithm, compression.level);
    }
    
    println!("Key derivation: {} ({}MB, {} iterations, {} threads)", 
             header.kdf.algorithm, 
             header.kdf.memory_cost / 1024,
             header.kdf.time_cost,
             header.kdf.parallelism);
    println!("Chunked encryption: {}KB chunks", header.chunk_size / 1024);
}

/// Stream decrypt a TAR-based encrypted file, handling both single files and directories
pub fn stream_decrypt_tar(
    input_path: &str,
    output_path: &str,
    password: &str,
) -> Result<()> {
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
    
    // Display encryption details
    display_decryption_info(&header);
    
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
    
    // Get file size to calculate ciphertext size
    let file_metadata = std::fs::metadata(input_path)
        .with_context(|| format!("Failed to get file metadata: {}", input_path))?;
    let total_file_size = file_metadata.len();
    let ciphertext_size = total_file_size - 4 - header_length as u64; // Subtract header length and header data
    
    // Create progress bar for decryption and extraction
    println!("Decrypting data...");
    let decrypt_pb = create_byte_progress_bar(ciphertext_size, "Decrypting and extracting");
    
    // Create streaming decryption reader
    let decryption_reader = StreamingDecryptionReader::new(
        reader,
        algorithm.clone(),
        key,
        header.nonce.clone(),
        &header.salt,
        ciphertext_size,
    )?;
    
    // Wrap with progress tracking
    let progress_reader = ProgressTrackingReader::new(decryption_reader, decrypt_pb.clone());
    
    // Create decompression reader if needed
    let decompressed_reader: Box<dyn Read> = if let Some(ref compression) = header.compression {
        let compression_alg = CompressionAlgorithm::from_string(&compression.algorithm)?;
        match compression_alg {
            CompressionAlgorithm::None => Box::new(progress_reader),
            CompressionAlgorithm::Zstd => {
                println!("Setting up streaming decompression with zstd...");
                Box::new(zstd::Decoder::new(progress_reader)
                    .context("Failed to create zstd decoder")?)
            }
        }
    } else {
        Box::new(progress_reader)
    };
    
    // Create TAR archive from the streaming reader and extract directly
    println!("Setting up streaming TAR extraction...");
    let mut tar_archive = tar::Archive::new(decompressed_reader);
    
    // Try to extract as a directory first
    println!("Decrypting and extracting data...");
    
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
    
    // Wrap with progress tracking using the same progress bar
    let progress_reader2 = ProgressTrackingReader::new(decryption_reader2, decrypt_pb.clone());
    
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
    
    if entry_count == 1 {
        // Single file in TAR - extract to the output path directly
        println!("Extracting single file to: {}", output_path);
        let mut entries = tar_archive2.entries()?;
        if let Some(entry) = entries.next() {
            let mut entry = entry.context("Failed to read TAR entry")?;
            let mut output_file = File::create(output_path)
                .with_context(|| format!("Failed to create output file: {}", output_path))?;
            
            std::io::copy(&mut entry, &mut output_file)
                .context("Failed to extract file from TAR")?;
            
            println!("File extracted successfully: {}", output_path);
        } else {
            bail!("TAR archive is empty");
        }
    } else {
        
        fs::create_dir_all(output_path)
            .with_context(|| format!("Failed to create output directory: {}", output_path))?;
        
        tar_archive2.unpack(output_path)
            .with_context(|| format!("Failed to extract TAR archive to: {}", output_path))?;
        
    }
    
    // Complete the progress bar
    decrypt_pb.finish_with_message("Decryption and extraction complete");
    
    // Verify HMAC for file integrity after extraction is complete
    // We need to read the HMAC from the end of the file since the streaming reader
    // consumed all the ciphertext but hasn't verified the HMAC yet
    println!("Verifying file integrity...");
    
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
    // This is necessary because we need to verify the HMAC against the plaintext
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
    
    println!("File integrity verified successfully");
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
        
        // Corrupt the header by setting an impossibly large header length
        let mut encrypted_data = fs::read(&encrypted_file).unwrap();
        // Set header length to maximum u32 value to guarantee it exceeds file size
        encrypted_data[0] = 0xFF;
        encrypted_data[1] = 0xFF;
        encrypted_data[2] = 0xFF;
        encrypted_data[3] = 0xFF;
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
