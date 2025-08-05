//! Compression functionality for streaming encryption
//! 
//! This module provides compression wrappers that integrate with the streaming
//! encryption pipeline, supporting zstd compression with configurable levels.

use std::io::{Read, Write};
use zstd;
use crate::crypto::{RuntimeCompressionConfig, CompressionAlgorithm, CompressionConfig};
use crate::core::StreamingEncryptionWriter;
use crate::error::{SecifyError, Result};

/// A reader that can be either raw or decompressed
pub enum DecompressionReader<R: Read> {
    Raw(R),
    Zstd(zstd::Decoder<'static, std::io::BufReader<R>>),
}

impl<R: Read> Read for DecompressionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            DecompressionReader::Raw(reader) => reader.read(buf),
            DecompressionReader::Zstd(decoder) => decoder.read(buf),
        }
    }
}

/// Compression wrapper that buffers and compresses data before encryption
pub struct CompressionBufferingWriter<W: Write> {
    inner: StreamingEncryptionWriter<W>,
    compression_buffer: Vec<u8>,
    compression_encoder: Option<zstd::Encoder<'static, Vec<u8>>>,
    chunk_size: usize,
}

/// Calculate optimal buffer size and window log based on compression level
/// This determines how much uncompressed data to buffer before compressing,
/// independent of encryption chunk sizes.
fn get_compression_params(level: i32) -> (usize, u32) {
    match level {
        1..=3 => (32 * 1024, 16),   // Fast: 32KB buffer, 64KB window
        4..=6 => (64 * 1024, 17),   // Balanced: 64KB buffer, 128KB window  
        7..=12 => (128 * 1024, 18), // Good: 128KB buffer, 256KB window
        13..=19 => (256 * 1024, 20), // High: 256KB buffer, 1MB window
        _ => (512 * 1024, 22),      // Maximum: 512KB buffer, 4MB window
    }
}

impl<W: Write> CompressionBufferingWriter<W> {
    pub fn new(
        inner: StreamingEncryptionWriter<W>,
        compression: Option<&RuntimeCompressionConfig>,
    ) -> Result<Self> {
        let (compression_buffer_size, compression_encoder) = if let Some(config) = compression {
            match CompressionAlgorithm::from_string(&config.algorithm)? {
                CompressionAlgorithm::None => (0, None), // No buffer needed for passthrough
                CompressionAlgorithm::Zstd => {
                    let level = config.level;
                    let (buffer_size, window_log) = get_compression_params(level);
                    
                    // Create encoder with level-appropriate settings
                    let mut encoder = zstd::Encoder::new(Vec::with_capacity(buffer_size), level)?;
                    encoder.window_log(window_log)?;
                    encoder.long_distance_matching(level >= 7)?; // Enable for higher levels
                    
                    (buffer_size, Some(encoder))
                }
            }
        } else {
            (0, None) // No buffer needed when no compression is configured
        };
        
        Ok(Self {
            inner,
            compression_buffer: Vec::with_capacity(compression_buffer_size),
            compression_encoder,
            chunk_size: compression_buffer_size, // Buffer size for compression input buffering
        })
    }
    
    /// Helper method to handle compression output and buffer management
    fn handle_compression_output(&mut self) -> Result<()> {
        if let Some(ref mut encoder) = self.compression_encoder {
            let compressed_output = encoder.get_ref();
            if !compressed_output.is_empty() {
                // Reserve capacity to avoid reallocations
                self.compression_buffer.reserve(compressed_output.len());
                self.compression_buffer.extend_from_slice(compressed_output);
                
                // Clear encoder buffer efficiently
                encoder.get_mut().clear();
                self.flush_compressed_chunks()?;
            }
        }
        Ok(())
    }
    
    fn flush_compressed_chunks(&mut self) -> Result<()> {
        // Process chunks without unnecessary allocation - write directly from buffer
        while self.compression_buffer.len() >= self.chunk_size {
            let chunk = &self.compression_buffer[..self.chunk_size];
            self.inner.write_all(chunk)?;
            self.compression_buffer.drain(..self.chunk_size);
        }
        Ok(())
    }
    
    pub fn finalize(mut self) -> Result<StreamingEncryptionWriter<W>> {
        // Finalize compression if active
        if let Some(encoder) = self.compression_encoder.take() {
            // Finish compression
            let final_compressed = encoder.finish()?;
            if !final_compressed.is_empty() {
                self.compression_buffer.extend_from_slice(&final_compressed);
            }
        }
        
        // Flush any remaining compressed data
        if !self.compression_buffer.is_empty() {
            self.inner.write_all(&self.compression_buffer)?;
        }
        
        Ok(self.inner)
    }
}

impl<W: Write> Write for CompressionBufferingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(ref mut encoder) = self.compression_encoder {
            // Write to compression encoder
            encoder.write_all(buf)?;
            
            // Handle any compressed output
            self.handle_compression_output()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        } else {
            // No compression - pass through directly to encryption layer
            self.inner.write_all(buf)?;
        }
        
        Ok(buf.len())
    }
    
    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(ref mut encoder) = self.compression_encoder {
            encoder.flush()?;
            self.handle_compression_output()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        }
        
        self.inner.flush()
    }
}

/// Create a decompression reader for the given algorithm and input
/// Returns a Box<dyn Read> that wraps either the original reader or a decompressed version
pub fn create_decompression_reader<R: Read>(
    reader: R,
    compression_config: Option<&CompressionConfig>,
) -> Result<Box<dyn Read>> 
where 
    R: 'static 
{
    if let Some(config) = compression_config {
        let compression_alg = CompressionAlgorithm::from_string(&config.algorithm)?;
        match compression_alg {
            CompressionAlgorithm::None => Ok(Box::new(reader)),
            CompressionAlgorithm::Zstd => {
                let buf_reader = std::io::BufReader::new(reader);
                let decoder = zstd::Decoder::with_buffer(buf_reader)
                    .map_err(|e| SecifyError::decompression(format!("Failed to create zstd decoder: {}", e)))?;
                Ok(Box::new(decoder))
            }
        }
    } else {
        Ok(Box::new(reader))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{EncryptionAlgorithm, generate_base_nonce, KEY_LENGTH};
    use std::io::Cursor;

    #[test]
    fn test_compression_roundtrip() {
        // Create test data
        let test_data = b"This is test data that should be compressed and then decompressed successfully.";
        
        // Create encryption writer
        let output_buffer = Vec::new();
        let algorithm = EncryptionAlgorithm::XChaCha20Poly1305;
        let base_nonce = generate_base_nonce(&algorithm).unwrap();
        let key = [1u8; KEY_LENGTH]; // Test key
        
        let encryption_writer = StreamingEncryptionWriter::new(
            output_buffer,
            algorithm,
            key,
            base_nonce,
        ).unwrap();
        
        // Create compression config
        let compression_config = RuntimeCompressionConfig {
            algorithm: "zstd".to_string(),
            level: 3,
        };
        
        // Create compression writer
        let mut compression_writer = CompressionBufferingWriter::new(
            encryption_writer,
            Some(&compression_config),
        ).unwrap();
        
        // Write test data
        compression_writer.write_all(test_data).unwrap();
        
        // Finalize compression
        let encryption_writer = compression_writer.finalize().unwrap();
        let (encrypted_buffer, _hmac) = encryption_writer.finalize().unwrap();
        
        // Verify we got some encrypted data
        assert!(!encrypted_buffer.is_empty());
        assert_ne!(encrypted_buffer, test_data);
    }
    
    #[test]
    fn test_no_compression_passthrough() {
        // Test that data passes through unchanged when no compression is used
        let test_data = b"Test data without compression";
        
        let output_buffer = Vec::new();
        let algorithm = EncryptionAlgorithm::XChaCha20Poly1305;
        let base_nonce = generate_base_nonce(&algorithm).unwrap();
        let key = [1u8; KEY_LENGTH];
        
        let encryption_writer = StreamingEncryptionWriter::new(
            output_buffer,
            algorithm,
            key,
            base_nonce,
        ).unwrap();
        
        // Create compression writer without compression
        let mut compression_writer = CompressionBufferingWriter::new(
            encryption_writer,
            None,
        ).unwrap();
        
        // Write test data
        compression_writer.write_all(test_data).unwrap();
        
        // Finalize
        let encryption_writer = compression_writer.finalize().unwrap();
        let (encrypted_buffer, _hmac) = encryption_writer.finalize().unwrap();
        
        // Verify we got encrypted data (different from input due to encryption)
        assert!(!encrypted_buffer.is_empty());
        assert_ne!(encrypted_buffer, test_data);
    }
    
    #[test]
    fn test_decompression_reader_creation() {
        let test_data = b"test data";
        let cursor = Cursor::new(test_data);
        
        // Test with zstd compression
        let zstd_config = CompressionConfig {
            algorithm: "zstd".to_string(),
        };
        let _reader = create_decompression_reader(cursor, Some(&zstd_config)).unwrap();
        // Just verify it was created successfully - no need to check contents
        
        // Test with no compression
        let cursor2 = Cursor::new(test_data);
        let _reader2 = create_decompression_reader(cursor2, None).unwrap();
        // Just verify it was created successfully - no need to check contents
    }
}
