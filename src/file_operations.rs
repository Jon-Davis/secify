use std::fs;
use std::path::Path;
use std::io::{Write, Cursor};
use anyhow::{Result, Context, bail};
use zip::{ZipWriter, ZipArchive, write::FileOptions, CompressionMethod};
use indicatif::ProgressBar;

use crate::crypto::*;
use crate::progress::*;

pub const WRITE_CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
pub const INITIAL_BUFFER_SIZE: usize = 64 * 1024; // 64KB

pub fn validate_file_size(file_path: &Path) -> Result<u64> {
    let metadata = fs::metadata(file_path)
        .with_context(|| format!("Failed to read file metadata: {}", file_path.display()))?;
    
    let file_size = metadata.len();
    
    if file_size > MAX_FILE_SIZE {
        bail!("File too large: {} bytes (maximum: {} bytes). Large files should be processed in chunks.", 
              file_size, MAX_FILE_SIZE);
    }
    
    if file_size == 0 {
        bail!("Cannot encrypt empty file: {}", file_path.display());
    }
    
    Ok(file_size)
}

pub fn count_files_in_directory(dir_path: &Path) -> Result<u64> {
    let mut count = 0;
    let entries = fs::read_dir(dir_path)
        .with_context(|| format!("Failed to read directory: {}", dir_path.display()))?;
    
    for entry in entries {
        let entry = entry.context("Failed to read directory entry")?;
        let path = entry.path();
        
        if path.is_dir() {
            count += 1; // Count the directory itself
            count += count_files_in_directory(&path)?; // Recursively count contents
        } else {
            count += 1; // Count the file
        }
    }
    
    Ok(count)
}

pub fn zip_directory(dir_path: &Path) -> Result<Vec<u8>> {
    // Count total files for progress tracking
    println!("Counting files...");
    let total_files = count_files_in_directory(dir_path)?;
    
    // Create progress bar
    let pb = create_standard_progress_bar(total_files, "Zipping");
    pb.set_message("Preparing...");
    
    // Pre-allocate buffer with estimated size for better performance
    let buffer = Vec::with_capacity(INITIAL_BUFFER_SIZE);
    let mut zip = ZipWriter::new(Cursor::new(buffer));
    
    // Use no compression for maximum speed
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .large_file(true); // Enable ZIP64 for large files
    
    let mut processed_files = 0;
    zip_directory_recursive(dir_path, dir_path, &mut zip, &options, &pb, &mut processed_files)?;
    
    pb.finish_with_message("Zipping complete!");
    
    let cursor = zip.finish().context("Failed to finish zip archive")?;
    Ok(cursor.into_inner())
}

fn zip_directory_recursive(
    base_path: &Path,
    current_path: &Path,
    zip: &mut ZipWriter<Cursor<Vec<u8>>>,
    options: &FileOptions,
    pb: &ProgressBar,
    processed_files: &mut u64,
) -> Result<()> {
    let entries = fs::read_dir(current_path)
        .with_context(|| format!("Failed to read directory: {}", current_path.display()))?;
    
    for entry in entries {
        let entry = entry.context("Failed to read directory entry")?;
        let path = entry.path();
        let relative_path = path.strip_prefix(base_path)
            .context("Failed to create relative path")?;
        
        if path.is_dir() {
            // Add directory entry
            let dir_name = format!("{}/", relative_path.to_string_lossy());
            zip.add_directory(dir_name, *options)
                .context("Failed to add directory to zip")?;
            
            // Update progress
            *processed_files += 1;
            pb.set_position(*processed_files);
            pb.set_message(format!("Adding directory: {}", relative_path.display()));
            
            // Recursively add directory contents
            zip_directory_recursive(base_path, &path, zip, options, pb, processed_files)?;
        } else {
            // Add file
            let file_name = relative_path.to_string_lossy().to_string();
            zip.start_file(file_name, *options)
                .context("Failed to start file in zip")?;
            
            // Read and write file in chunks for better memory usage
            let mut file = fs::File::open(&path)
                .with_context(|| format!("Failed to open file: {}", path.display()))?;
            
            std::io::copy(&mut file, zip)
                .context("Failed to write file to zip")?;
            
            // Update progress
            *processed_files += 1;
            pb.set_position(*processed_files);
            pb.set_message(format!("Adding file: {}", relative_path.display()));
        }
    }
    
    Ok(())
}

pub fn unzip_to_directory(zip_data: &[u8], output_dir: &Path) -> Result<()> {
    let cursor = Cursor::new(zip_data);
    let mut archive = ZipArchive::new(cursor)
        .context("Failed to read zip archive")?;
    
    // Create progress bar for extraction
    let total_files = archive.len() as u64;
    let pb = create_standard_progress_bar(total_files, "Extracting");
    pb.set_message("Preparing...");
    
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)
            .context("Failed to read file from zip")?;
        
        let outpath = output_dir.join(file.mangled_name());
        
        if file.name().ends_with('/') {
            // Directory
            fs::create_dir_all(&outpath)
                .with_context(|| format!("Failed to create directory: {}", outpath.display()))?;
            pb.set_message(format!("Creating directory: {}", file.name()));
        } else {
            // File
            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create parent directory: {}", parent.display()))?;
            }
            
            let mut outfile = fs::File::create(&outpath)
                .with_context(|| format!("Failed to create file: {}", outpath.display()))?;
            
            std::io::copy(&mut file, &mut outfile)
                .context("Failed to extract file from zip")?;
            
            pb.set_message(format!("Extracting: {}", file.name()));
        }
        
        pb.inc(1);
    }
    
    pb.finish_with_message("Extraction complete!");
    Ok(())
}

pub fn encrypt_file(file_path: &str, password: &str, algorithm: &EncryptionAlgorithm) -> Result<()> {
    let path = Path::new(file_path);
    
    // Validate file/directory exists and check size for files
    if !path.exists() {
        bail!("File or directory does not exist: {}", file_path);
    }
    
    // For files (not directories), validate size to prevent OOM
    if path.is_file() {
        validate_file_size(path)?;
    }
    
    // Generate cryptographically secure random salt and nonce
    let mut salt = [0u8; SALT_LENGTH];
    let nonce_length = algorithm.nonce_length();
    let mut nonce_bytes = vec![0u8; nonce_length];
    
    generate_secure_random_bytes(&mut salt)?;
    generate_secure_random_bytes(&mut nonce_bytes)?;
    
    // Derive encryption key from password and salt (this is the slow step)
    let key = derive_key(password, &salt)?;
    
    // Now do the progress-tracked operations
    // Determine what we're encrypting
    let (input_data, is_directory) = if path.is_dir() {
        println!("Zipping directory...");
        let zip_data = zip_directory(path)?;
        (zip_data, true)
    } else {
        // Read the input file
        let file_data = fs::read(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path))?;
        (file_data, false)
    };
    
    // Encrypt the data
    println!("Encrypting data...");
    let ciphertext = encrypt_data(&algorithm, &key, &nonce_bytes, &input_data)?;
    
    // Create CBOR header with encryption details
    let header = create_encryption_header(&salt, &nonce_bytes, is_directory, &algorithm);
    let cbor_header = serialize_header_to_cbor(&header)?;
    
    // Create output file structure: 
    // 4 bytes: CBOR header length (little-endian u32)
    // N bytes: CBOR header
    // remaining: ciphertext
    let mut output_data = Vec::new();
    output_data.extend_from_slice(&(cbor_header.len() as u32).to_le_bytes());
    output_data.extend_from_slice(&cbor_header);
    output_data.extend_from_slice(&ciphertext);
    
    // Write to .sec file with progress
    // Remove trailing path separators before adding .sec extension
    let clean_path = file_path.trim_end_matches('/').trim_end_matches('\\');
    let output_path = format!("{}.sec", clean_path);
    
    println!("Writing encrypted file...");
    let write_pb = create_byte_progress_bar(output_data.len() as u64, "Writing");
    
    // Write in chunks to show progress
    let mut output_file = fs::File::create(&output_path)
        .with_context(|| format!("Failed to create encrypted file: {}", output_path))?;
    
    for chunk in output_data.chunks(WRITE_CHUNK_SIZE) {
        output_file.write_all(chunk)
            .context("Failed to write encrypted data")?;
        write_pb.inc(chunk.len() as u64);
    }
    
    write_pb.finish_with_message("Writing complete");
    
    if is_directory {
        println!("Directory zipped and encrypted successfully: {}", output_path);
    } else {
        println!("File encrypted successfully: {}", output_path);
    }
    Ok(())
}

pub fn decrypt_file(file_path: &str, password: &str) -> Result<()> {
    // Ensure the file has .sec extension
    if !file_path.ends_with(".sec") {
        bail!("File must have .sec extension");
    }
    
    // Read the encrypted file
    let encrypted_data = fs::read(file_path)
        .with_context(|| format!("Failed to read encrypted file: {}", file_path))?;
    
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
    let ciphertext = &encrypted_data[4 + header_length..];
    
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
    println!("Content type: {:?}", header.content_type);
    
    let is_directory = matches!(header.content_type, ContentType::Directory);
    
    // Parse the encryption algorithm from header
    let algorithm = EncryptionAlgorithm::from_string(&header.encryption_algorithm)?;
    
    // Derive decryption key from password and salt from header
    let key = derive_key(password, &header.salt)?;
    
    // Decrypt the data
    println!("Decrypting data...");
    let decrypt_pb = create_byte_progress_bar(ciphertext.len() as u64, "Decrypting");
    
    let plaintext = decrypt_data(&algorithm, &key, &header.nonce, ciphertext)?;
    
    decrypt_pb.inc(ciphertext.len() as u64);
    decrypt_pb.finish_with_message("Decryption complete");
    
    // Determine output path (remove .sec extension)
    let output_path = &file_path[..file_path.len() - 4];
    
    if is_directory {
        // Check if output directory already exists
        if Path::new(output_path).exists() {
            bail!("Output directory already exists: {}", output_path);
        }
        
        // Create the output directory
        fs::create_dir_all(output_path)
            .with_context(|| format!("Failed to create output directory: {}", output_path))?;
        
        // Unzip the decrypted data to the directory
        println!("Unzipping directory...");
        unzip_to_directory(&plaintext, Path::new(output_path))?;
        
        println!("Directory decrypted and unzipped successfully: {}", output_path);
    } else {
        // Check if output file already exists
        if Path::new(output_path).exists() {
            bail!("Output file already exists: {}", output_path);
        }
        
        // Write decrypted data with progress
        println!("Writing decrypted file...");
        let write_pb = create_byte_progress_bar(plaintext.len() as u64, "Writing");
        
        let mut output_file = fs::File::create(output_path)
            .with_context(|| format!("Failed to create decrypted file: {}", output_path))?;
        
        for chunk in plaintext.chunks(WRITE_CHUNK_SIZE) {
            output_file.write_all(chunk)
                .context("Failed to write decrypted data")?;
            write_pb.inc(chunk.len() as u64);
        }
        
        write_pb.finish_with_message("Writing complete");
        
        println!("File decrypted successfully: {}", output_path);
    }
    
    Ok(())
}
