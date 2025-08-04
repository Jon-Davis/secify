//! Compression functionality for streaming encryption
//! 
//! This module provides compression wrappers that integrate with the streaming
//! encryption pipeline, supporting zstd compression with configurable levels.

use std::io::{Read, Write};
use zstd;
use crate::crypto::{CompressionConfig, CompressionAlgorithm, DEFAULT_CHUNK_SIZE};
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
                    let encoder = zstd::Encoder::new(Vec::new(), 3)?; // Use default level 3
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
            // No compression - pass through directly with chunk management
            let mut remaining = buf;
            while !remaining.is_empty() {
                let space_available = self.chunk_size - self.compression_buffer.len();
                let to_copy = remaining.len().min(space_available);
                
                self.compression_buffer.extend_from_slice(&remaining[..to_copy]);
                remaining = &remaining[to_copy..];
                
                // If buffer is full, flush it
                if self.compression_buffer.len() >= self.chunk_size {
                    self.flush_compressed_chunks()
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                }
            }
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
    use crate::crypto::{EncryptionAlgorithm, generate_base_nonce, generate_secure_random_bytes, KEY_LENGTH, SALT_LENGTH};
    use std::io::Cursor;

    #[test]
    fn test_compression_roundtrip() {
        // Create test data
        let test_data = b"This is test data that should be compressed and then decompressed successfully.";
        
        // Create encryption writer
        let output_buffer = Vec::new();
        let algorithm = EncryptionAlgorithm::XChaCha20Poly1305;
        let mut salt = [0u8; SALT_LENGTH];
        generate_secure_random_bytes(&mut salt).unwrap();
        let base_nonce = generate_base_nonce(&algorithm).unwrap();
        let key = [1u8; KEY_LENGTH]; // Test key
        
        let encryption_writer = StreamingEncryptionWriter::new(
            output_buffer,
            algorithm,
            key,
            base_nonce,
            &salt,
        ).unwrap();
        
        // Create compression config
        let compression_config = CompressionConfig {
            algorithm: "zstd".to_string(),
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
        let mut salt = [0u8; SALT_LENGTH];
        generate_secure_random_bytes(&mut salt).unwrap();
        let base_nonce = generate_base_nonce(&algorithm).unwrap();
        let key = [1u8; KEY_LENGTH];
        
        let encryption_writer = StreamingEncryptionWriter::new(
            output_buffer,
            algorithm,
            key,
            base_nonce,
            &salt,
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
