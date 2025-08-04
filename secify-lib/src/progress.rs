//! Progress reporting types for encryption and decryption operations
//! 
//! This module provides progress callback types and progress information enums
//! for both encryption and decryption operations.

use std::sync::Arc;
use std::io::Read;

/// Log level for event messages
#[derive(Debug, Clone)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

/// Unified event system for all operations
#[derive(Debug, Clone)]
pub enum SecifyEvent {
    /// Progress events for encryption
    EncryptProgress(EncryptProgress),
    /// Progress events for decryption
    DecryptProgress(DecryptProgress),
    /// Log events with severity
    Log { level: LogLevel, message: String },
}

/// Single callback type for all events - optional
pub type EventCallback = Arc<dyn Fn(SecifyEvent) + Send + Sync>;

/// Helper function to create a no-op event callback
pub fn no_op_callback() -> EventCallback {
    Arc::new(|_| {})
}

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
    /// Decryption complete
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

/// Progress-aware reader wrapper that reports bytes read during decryption
pub struct ProgressAwareReader<R: Read> {
    inner: R,
    bytes_read: u64,
    total_bytes: u64,
    event_callback: EventCallback,
}

impl<R: Read> ProgressAwareReader<R> {
    pub fn new(inner: R, total_bytes: u64, event_callback: EventCallback) -> Self {
        Self {
            inner,
            bytes_read: 0,
            total_bytes,
            event_callback,
        }
    }
}

impl<R: Read> Read for ProgressAwareReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.inner.read(buf)?;
        self.bytes_read += bytes_read as u64;
        (self.event_callback)(SecifyEvent::DecryptProgress(DecryptProgress::BytesProcessed {
            current: self.bytes_read,
            total: self.total_bytes,
        }));
        Ok(bytes_read)
    }
}
