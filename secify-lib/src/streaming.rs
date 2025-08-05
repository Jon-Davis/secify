//! Streaming encryption and decryption primitives
//! 
//! This module provides the low-level streaming writers and readers for chunk-based
//! encryption and decryption operations.

use std::io::{Read, Write, BufReader};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::*;
use crate::error::{SecifyError, Result};

/// HMAC size in bytes (SHA256)
const HMAC_SIZE: usize = 32;

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
        
        let hmac = Hmac::<Sha256>::new_from_slice(salt)
            .map_err(|_| SecifyError::crypto("Failed to create HMAC".to_string()))?;
        
        Ok(Self {
            inner,
            algorithm,
            key,
            base_nonce,
            chunk_counter: 0,
            buffer: Vec::with_capacity(chunk_size),
            chunk_size,
            hmac,
        })
    }

    fn encrypt_chunk(&mut self, data: &[u8], is_final: bool) -> Result<()> {
        let nonce = create_streaming_chunk_nonce(&self.algorithm, &self.base_nonce, self.chunk_counter)?;
        let encrypted = encrypt_data(&self.algorithm, &self.key, &nonce, data)?;
        
        // Write chunk to output
        self.inner.write_all(&encrypted)?;
        
        // Update HMAC with encrypted chunk
        self.hmac.update(&data);
        
        if is_final {
            // Write final HMAC
            let hmac_result = self.hmac.clone().finalize().into_bytes();
            self.inner.write_all(&hmac_result)?;
        }
        
        self.chunk_counter += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Result<W> {
        // Encrypt any remaining data in buffer
        if !self.buffer.is_empty() {
            let data = std::mem::take(&mut self.buffer);
            self.encrypt_chunk(&data, true)?;
        } else {
            // Even if buffer is empty, we need to write the HMAC
            let hmac_result = self.hmac.clone().finalize().into_bytes();
            self.inner.write_all(&hmac_result)?;
        }
        
        Ok(self.inner)
    }
}

impl<W: Write> Write for StreamingEncryptionWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut bytes_written = 0;
        let mut remaining = buf;
        
        while !remaining.is_empty() {
            let space_left = self.chunk_size - self.buffer.len();
            let to_copy = remaining.len().min(space_left);
            
            self.buffer.extend_from_slice(&remaining[..to_copy]);
            remaining = &remaining[to_copy..];
            bytes_written += to_copy;
            
            if self.buffer.len() == self.chunk_size {
                let data = std::mem::take(&mut self.buffer);
                self.encrypt_chunk(&data, false)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            }
        }
        
        Ok(bytes_written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Core streaming decryption reader without UI dependencies
pub struct StreamingDecryptionReader<R: Read> {
    inner: BufReader<R>,
    algorithm: EncryptionAlgorithm,
    key: [u8; KEY_LENGTH],
    base_nonce: Vec<u8>,
    chunk_counter: u64,
    current_chunk: Vec<u8>,
    chunk_pos: usize,
    chunk_size: usize,
    hmac: Hmac<Sha256>,
    finished: bool,
}

impl<R: Read> StreamingDecryptionReader<R> {
    pub fn new(
        inner: R,
        algorithm: EncryptionAlgorithm,
        key: [u8; KEY_LENGTH],
        base_nonce: Vec<u8>,
        salt: &[u8],
    ) -> Result<Self> {
        let chunk_size = DEFAULT_CHUNK_SIZE;
        
        let hmac = Hmac::<Sha256>::new_from_slice(salt)
            .map_err(|_| SecifyError::crypto("Failed to create HMAC".to_string()))?;
        
        Ok(Self {
            inner: BufReader::new(inner),
            algorithm,
            key,
            base_nonce,
            chunk_counter: 0,
            current_chunk: Vec::new(),
            chunk_pos: 0,
            chunk_size,
            hmac,
            finished: false,
        })
    }

    fn read_next_chunk(&mut self) -> Result<bool> {
        // Read chunk data
        let mut chunk_data = vec![0u8; self.chunk_size];
        let bytes_read = self.inner.read(&mut chunk_data)?;
        
        if bytes_read == 0 {
            // Check if we're at the end and validate HMAC
            if !self.finished {
                let mut hmac_buffer = [0u8; HMAC_SIZE];
                let hmac_bytes_read = self.inner.read(&mut hmac_buffer)?;
                
                if hmac_bytes_read == HMAC_SIZE {
                    let expected_hmac = self.hmac.clone().finalize().into_bytes();
                    if hmac_buffer[..] != expected_hmac[..] {
                        return Err(SecifyError::authentication("HMAC verification failed".to_string()));
                    }
                }
                
                self.finished = true;
            }
            return Ok(false);
        }
        
        chunk_data.truncate(bytes_read);
        
        // Update HMAC with encrypted chunk before decryption
        self.hmac.update(&chunk_data);
        
        // Decrypt chunk
        let nonce = create_streaming_chunk_nonce(&self.algorithm, &self.base_nonce, self.chunk_counter)?;
        let decrypted = decrypt_data(&self.algorithm, &self.key, &nonce, &chunk_data)?;
        
        self.current_chunk = decrypted;
        self.chunk_pos = 0;
        self.chunk_counter += 1;
        
        Ok(true)
    }
}

impl<R: Read> Read for StreamingDecryptionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.finished {
            return Ok(0);
        }
        
        let mut bytes_read = 0;
        
        while bytes_read < buf.len() {
            // If current chunk is exhausted, read next chunk
            if self.chunk_pos >= self.current_chunk.len() {
                match self.read_next_chunk() {
                    Ok(true) => {}, // Continue with new chunk
                    Ok(false) => break, // No more chunks
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                }
            }
            
            if self.chunk_pos < self.current_chunk.len() {
                let remaining_in_chunk = self.current_chunk.len() - self.chunk_pos;
                let remaining_in_buf = buf.len() - bytes_read;
                let to_copy = remaining_in_chunk.min(remaining_in_buf);
                
                buf[bytes_read..bytes_read + to_copy]
                    .copy_from_slice(&self.current_chunk[self.chunk_pos..self.chunk_pos + to_copy]);
                
                self.chunk_pos += to_copy;
                bytes_read += to_copy;
            }
        }
        
        Ok(bytes_read)
    }
}

/// Create a nonce for a specific chunk in streaming encryption
pub fn create_streaming_chunk_nonce(algorithm: &EncryptionAlgorithm, base_nonce: &[u8], chunk_counter: u64) -> Result<Vec<u8>> {
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
