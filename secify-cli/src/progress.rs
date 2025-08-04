//! CLI-specific progress tracking and user interface
//! 
//! This module wraps the core library functions with progress bars and console output.

use std::time::Instant;
use std::rc::Rc;
use std::cell::RefCell;
use secify_lib::{
    encrypt_core, decrypt_core, 
    EncryptProgress, DecryptProgress, EncryptionAlgorithm, Argon2Params, CompressionConfig,
    Result as SecifyResult
};
use indicatif::{ProgressBar, ProgressStyle};

/// Create a standard progress bar for file counting operations
pub fn create_standard_progress_bar(total: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message(message.to_string());
    pb
}

/// Create a progress bar for byte-based operations
pub fn create_byte_progress_bar(total_bytes: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total_bytes);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} {msg} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message(message.to_string());
    pb
}

/// CLI wrapper for encryption with progress bars and console output
pub fn encrypt_with_ui(
    input_path: &str,
    output_path: &str,
    password: &str,
    algorithm: &EncryptionAlgorithm,
    argon2_params: &Argon2Params,
    compression: Option<CompressionConfig>,
) -> SecifyResult<()> {
    let progress_bar = Rc::new(RefCell::new(None::<ProgressBar>));
    let start_time = Instant::now();
    
    // Clone for the closure
    let progress_bar_clone = progress_bar.clone();
    
    // Progress callback that manages the progress bar
    let progress_callback = move |progress: EncryptProgress| {
        match progress {
            EncryptProgress::Starting { is_directory, has_compression } => {
                match (is_directory, has_compression) {
                    (true, true) => println!("Streaming directory encryption with compression and full pipeline (Archive → Compress → Encrypt)..."),
                    (true, false) => println!("Streaming directory encryption with full pipeline (Archive → Encrypt)..."),
                    (false, true) => println!("Streaming file encryption with compression pipeline (Compress → Encrypt)..."),
                    (false, false) => println!("Streaming file encryption..."),
                }
            },
            EncryptProgress::CountingFiles => {
                println!("Counting files...");
            },
            EncryptProgress::FileCountComplete { total_files } => {
                let pb = create_standard_progress_bar(total_files, "Processing files");
                *progress_bar_clone.borrow_mut() = Some(pb);
            },
            EncryptProgress::ProcessingFile { current, total: _, name } => {
                if let Some(ref pb) = *progress_bar_clone.borrow() {
                    pb.set_position(current);
                    pb.set_message(format!("Processing: {}", name));
                }
            },
            EncryptProgress::EncryptionStarted => {
                if let Some(ref pb) = *progress_bar_clone.borrow() {
                    pb.set_message("Finalizing encryption...");
                }
            },
            EncryptProgress::EncryptionComplete => {
                if let Some(ref pb) = *progress_bar_clone.borrow() {
                    pb.finish_with_message("Encryption complete");
                }
            },
        }
    };
    
    // Simple logging callback
    let log_callback = |message: &str| {
        // Only show important messages during progress tracking
        // Most log messages are redundant with progress indicators
        if message.contains("error") || message.contains("Error") || message.contains("failed") || message.contains("Failed") {
            println!("{}", message);
        }
        // Suppress routine messages like "Deriving encryption key..." to avoid disrupting progress bar
    };
    
    let result = encrypt_core(
        input_path,
        output_path,
        password,
        algorithm,
        argon2_params,
        compression,
        &progress_callback,
        &log_callback,
    );
    
    let elapsed = start_time.elapsed();
    println!("Total time: {:.2} seconds", elapsed.as_secs_f64());
    
    result
}

/// CLI wrapper for decryption with progress bars and console output
pub fn decrypt_with_ui(
    input_path: &str,
    output_path: &str,
    password: &str,
) -> SecifyResult<()> {
    let progress_bar = Rc::new(RefCell::new(None::<ProgressBar>));
    let start_time = Instant::now();
    
    // Clone for the closure
    let progress_bar_clone = progress_bar.clone();
    
    let progress_callback = move |progress: DecryptProgress| {
        match progress {
            DecryptProgress::DecryptionStarted { encryption_info, total_bytes: _ } => {
                // Display encryption info
                println!("File format version: {}", encryption_info.version);
                println!("Encryption: {}", encryption_info.algorithm);
                if let Some(ref compression) = encryption_info.compression {
                    println!("Compression: {}", compression);
                }
                println!("Key derivation: {}", encryption_info.kdf_info);
                println!("Chunked encryption: {}KB chunks", encryption_info.chunk_size / 1024);
                // Don't create progress bar yet - wait for ExtractionStrategy
            },
            DecryptProgress::BytesProcessed { current, total } => {
                if let Some(ref pb) = *progress_bar_clone.borrow() {
                    // Update progress bar total if it's different (first time)
                    if pb.length() != Some(total) {
                        pb.set_length(total);
                    }
                    pb.set_position(current);
                }
            },
            DecryptProgress::ExtractionStrategy { is_single_file, output_path } => {
                let strategy = if is_single_file {
                    format!("Extracting single file to: {}", output_path)
                } else {
                    format!("Extracting directory to: {}", output_path)
                };
                println!("{}", strategy);
                
                // Now create the progress bar for decryption and extraction
                println!("Decrypting and extracting data...");
                // Use a reasonable estimate for total bytes (will be updated by BytesProcessed)
                let pb = create_byte_progress_bar(100_000_000, "Decrypting and extracting"); // 100MB default
                *progress_bar_clone.borrow_mut() = Some(pb);
            },
            DecryptProgress::VerifyingIntegrity => {
                if let Some(ref pb) = *progress_bar_clone.borrow() {
                    pb.set_message("Verifying integrity");
                }
                println!("Verifying file integrity...");
            },
            DecryptProgress::DecryptionComplete => {
                // Just print completion message, don't use progress bar
                if let Some(ref pb) = *progress_bar_clone.borrow() {
                    pb.finish_and_clear();
                }
                println!("Decryption and extraction complete");
            },
        }
    };
    
    let log_callback = |message: &str| {
        // Only show important messages during progress tracking
        // Most log messages are redundant with progress indicators
        if message.contains("error") || message.contains("Error") || message.contains("failed") || message.contains("Failed") {
            println!("{}", message);
        }
        // Suppress routine messages like "Setting up streaming..." to avoid disrupting progress bar
    };
    
    let result = decrypt_core(
        input_path,
        output_path,
        password,
        &progress_callback,
        &log_callback,
    );
    
    let elapsed = start_time.elapsed();
    println!("Total time: {:.2} seconds", elapsed.as_secs_f64());
    
    result
}
