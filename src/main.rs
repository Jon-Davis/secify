use std::fs;
use std::path::Path;
use std::io::{self, Write};
use std::time::Instant;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use argon2::{Argon2, Algorithm, Version, Params, PasswordHasher};
use argon2::password_hash::{rand_core::RngCore, SaltString};
use clap::Parser;
use anyhow::{Result, Context, bail};
use zip::{ZipWriter, ZipArchive, write::FileOptions, CompressionMethod};
use std::io::Cursor;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Serialize, Deserialize};

#[derive(Parser)]
#[command(name = "aesify")]
#[command(about = "A CLI tool for encrypting and decrypting files and directories using AES-256-GCM with Argon2 key derivation")]
struct Cli {
    /// Input file or directory path (.sec files will be decrypted, others will be encrypted)
    file: Option<String>,
    /// Password for encryption/decryption
    #[arg(short, long)]
    password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct EncryptionHeader {
    /// File format version for future compatibility
    version: u32,
    /// Encryption algorithm identifier
    encryption_algorithm: String,
    /// Key derivation function details
    kdf: KeyDerivationConfig,
    /// Compression details
    compression: CompressionConfig,
    /// Content type (file or directory)
    content_type: ContentType,
    /// Salt for key derivation
    salt: Vec<u8>,
    /// Nonce/IV for encryption
    nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct KeyDerivationConfig {
    /// Algorithm name (e.g., "Argon2id")
    algorithm: String,
    /// Version of the algorithm
    version: String,
    /// Memory cost in KB
    memory_cost: u32,
    /// Time cost (iterations)
    time_cost: u32,
    /// Parallelism (number of threads)
    parallelism: u32,
    /// Output length in bytes
    output_length: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct CompressionConfig {
    /// Compression method used
    method: String,
    /// Whether compression was applied
    enabled: bool,
}

#[derive(Serialize, Deserialize, Debug)]
enum ContentType {
    File,
    Directory,
}

const SALT_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const KEY_LENGTH: usize = 32;
const FILE_FORMAT_VERSION: u32 = 1;

fn create_encryption_header(salt: &[u8], nonce: &[u8], is_directory: bool) -> EncryptionHeader {
    EncryptionHeader {
        version: FILE_FORMAT_VERSION,
        encryption_algorithm: "AES-256-GCM".to_string(),
        kdf: KeyDerivationConfig {
            algorithm: "Argon2id".to_string(),
            version: "0x13".to_string(),
            memory_cost: 131072, // 128 MB in KB
            time_cost: 8,
            parallelism: 4,
            output_length: KEY_LENGTH as u32,
        },
        compression: CompressionConfig {
            method: "ZIP-Stored".to_string(),
            enabled: is_directory,
        },
        content_type: if is_directory { ContentType::Directory } else { ContentType::File },
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
    }
}

fn serialize_header_to_cbor(header: &EncryptionHeader) -> Result<Vec<u8>> {
    let mut cbor_data = Vec::new();
    ciborium::ser::into_writer(header, &mut cbor_data)
        .context("Failed to serialize header to CBOR")?;
    Ok(cbor_data)
}

fn deserialize_header_from_cbor(cbor_data: &[u8]) -> Result<EncryptionHeader> {
    let header: EncryptionHeader = ciborium::de::from_reader(cbor_data)
        .context("Failed to deserialize header from CBOR")?;
    Ok(header)
}

fn validate_header(header: &EncryptionHeader) -> Result<()> {
    // Check version compatibility
    if header.version > FILE_FORMAT_VERSION {
        bail!("Unsupported file format version: {}. This tool supports up to version {}.", 
              header.version, FILE_FORMAT_VERSION);
    }
    
    // Validate encryption algorithm
    if header.encryption_algorithm != "AES-256-GCM" {
        bail!("Unsupported encryption algorithm: {}", header.encryption_algorithm);
    }
    
    // Validate KDF
    if header.kdf.algorithm != "Argon2id" {
        bail!("Unsupported key derivation function: {}", header.kdf.algorithm);
    }
    
    // Validate salt and nonce lengths
    if header.salt.len() != SALT_LENGTH {
        bail!("Invalid salt length: expected {}, got {}", SALT_LENGTH, header.salt.len());
    }
    
    if header.nonce.len() != NONCE_LENGTH {
        bail!("Invalid nonce length: expected {}, got {}", NONCE_LENGTH, header.nonce.len());
    }
    
    Ok(())
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LENGTH]> {
    // Explicit Argon2id parameters for security and transparency
    let params = Params::new(
        131072, // memory cost: 128 MB
        8,     // time cost: 8 iterations
        4,     // parallelism: 4 threads
        Some(KEY_LENGTH) // output length: 32 bytes
    ).map_err(|e| anyhow::anyhow!("Failed to create Argon2 params: {}", e))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| anyhow::anyhow!("Failed to encode salt: {}", e))?;
    
    println!("Deriving encryption key with Argon2id (128MB, 8 iterations, 4 threads)...");
    let start_time = Instant::now();
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
    
    let duration = start_time.elapsed();
    println!("Argon2 key derivation completed in {:.2} seconds", duration.as_secs_f64());
    
    let hash = password_hash.hash
        .context("No hash in password hash")?;
    let hash_bytes = hash.as_bytes();
    
    if hash_bytes.len() < KEY_LENGTH {
        bail!("Hash too short for key derivation");
    }
    
    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&hash_bytes[..KEY_LENGTH]);
    Ok(key)
}

fn count_files_in_directory(dir_path: &Path) -> Result<u64> {
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

fn zip_directory(dir_path: &Path) -> Result<Vec<u8>> {
    // Count total files for progress tracking
    println!("Counting files...");
    let total_files = count_files_in_directory(dir_path)?;
    
    // Create progress bar
    let pb = ProgressBar::new(total_files);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({msg})")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message("Zipping...");
    
    // Pre-allocate buffer with estimated size for better performance
    let buffer = Vec::with_capacity(1024 * 1024); // Start with 1MB
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
            
            io::copy(&mut file, zip)
                .context("Failed to write file to zip")?;
            
            // Update progress
            *processed_files += 1;
            pb.set_position(*processed_files);
            pb.set_message(format!("Adding file: {}", relative_path.display()));
        }
    }
    
    Ok(())
}

fn unzip_to_directory(zip_data: &[u8], output_dir: &Path) -> Result<()> {
    let cursor = Cursor::new(zip_data);
    let mut archive = ZipArchive::new(cursor)
        .context("Failed to read zip archive")?;
    
    // Create progress bar for extraction
    let total_files = archive.len() as u64;
    let pb = ProgressBar::new(total_files);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({msg})")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message("Extracting...");
    
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
            
            io::copy(&mut file, &mut outfile)
                .context("Failed to extract file from zip")?;
            
            pb.set_message(format!("Extracting: {}", file.name()));
        }
        
        pb.inc(1);
    }
    
    pb.finish_with_message("Extraction complete!");
    Ok(())
}

fn encrypt_file(file_path: &str, password: &str) -> Result<()> {
    let path = Path::new(file_path);
    
    // Generate random salt and nonce first
    let mut salt = [0u8; SALT_LENGTH];
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);
    
    // Derive encryption key from password and salt (this is the slow step)
    let key = derive_key(password, &salt)?;
    
    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;
    
    let nonce = Nonce::from_slice(&nonce_bytes);
    
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
    let ciphertext = cipher.encrypt(nonce, input_data.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to encrypt data: {}", e))?;
    
    // Create CBOR header with encryption details
    let header = create_encryption_header(&salt, &nonce_bytes, is_directory);
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
    let write_pb = ProgressBar::new(output_data.len() as u64);
    write_pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} Writing [{elapsed_precise}] [{bar:40.yellow/red}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    
    // Write in chunks to show progress
    let mut output_file = fs::File::create(&output_path)
        .with_context(|| format!("Failed to create encrypted file: {}", output_path))?;
    
    const WRITE_CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
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

fn decrypt_file(file_path: &str, password: &str) -> Result<()> {
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
    let header_length = u32::from_le_bytes([
        encrypted_data[0], encrypted_data[1], encrypted_data[2], encrypted_data[3]
    ]) as usize;
    
    // Validate header length
    if header_length > encrypted_data.len() - 4 || header_length == 0 {
        bail!("Invalid CBOR header length: {}", header_length);
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
    
    // Derive decryption key from password and salt from header
    let key = derive_key(password, &header.salt)?;
    
    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;
    
    let nonce = Nonce::from_slice(&header.nonce);
    
    // Decrypt the data
    println!("Decrypting data...");
    let decrypt_pb = ProgressBar::new(ciphertext.len() as u64);
    decrypt_pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} Decrypting [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt data - incorrect password or corrupted file: {}", e))?;
    
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
        let write_pb = ProgressBar::new(plaintext.len() as u64);
        write_pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} Writing [{elapsed_precise}] [{bar:40.yellow/red}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
        
        let mut output_file = fs::File::create(output_path)
            .with_context(|| format!("Failed to create decrypted file: {}", output_path))?;
        
        const WRITE_CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
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

fn prompt_user(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush().context("Failed to flush stdout")?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)
        .context("Failed to read user input")?;
    
    Ok(input.trim().to_string())
}

fn get_password(prompt: &str) -> Result<String> {
    // For now, we'll use regular input. In production, you might want to use
    // a crate like `rpassword` to hide password input
    prompt_user(prompt)
}

fn list_current_directory() -> Result<()> {
    let current_dir = std::env::current_dir()
        .context("Failed to get current directory")?;
    
    println!("\nFiles in current directory ({}):", current_dir.display());
    
    let entries = fs::read_dir(&current_dir)
        .context("Failed to read directory")?;
    
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    
    for entry in entries {
        let entry = entry.context("Failed to read directory entry")?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        
        if path.is_dir() {
            dirs.push(format!("{}/", name));
        } else {
            files.push(name);
        }
    }
    
    // Sort and display directories first, then files
    dirs.sort();
    files.sort();
    
    for dir in dirs {
        println!("  📁 {}", dir);
    }
    for file in files {
        println!("  📄 {}", file);
    }
    println!();
    
    Ok(())
}

fn interactive_mode() -> Result<()> {
    println!("=== AESify Interactive Mode ===\n");
    
    // Get file path
    let file_path = loop {
        let path = prompt_user("Enter the file or directory path (type 'ls' to list files): ")?;
        if path.is_empty() {
            println!("Path cannot be empty.");
            continue;
        }
        if path.to_lowercase() == "ls" || path.to_lowercase() == "dir" {
            list_current_directory()?;
            continue;
        }
        if !Path::new(&path).exists() {
            println!("File or directory '{}' does not exist. Please check the path.", path);
            continue;
        }
        break path;
    };
    
    // Determine operation based on file extension
    let is_decrypt = file_path.ends_with(".sec");
    
    if is_decrypt {
        println!("Detected .sec file - will decrypt");
    } else {
        println!("Detected non-.sec file - will encrypt");
    }
    
    // Get password
    let password = loop {
        let pass = get_password(&format!("Enter password for {}: ", if is_decrypt { "decryption" } else { "encryption" }))?;
        if pass.is_empty() {
            println!("Password cannot be empty.");
            continue;
        }
        if !is_decrypt {
            // Only require password confirmation for encryption
            if pass.len() < 4 {
                println!("Password should be at least 4 characters long for security.");
                continue;
            }
            
            let confirm = get_password("Confirm password: ")?;
            if pass != confirm {
                println!("Passwords do not match. Please try again.");
                continue;
            }
        }
        break pass;
    };
    
    // Perform the operation
    if is_decrypt {
        println!("\nDecrypting file...");
        decrypt_file(&file_path, &password)?;
    } else {
        println!("\nEncrypting file...");
        encrypt_file(&file_path, &password)?;
    }
    
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match (cli.file, cli.password) {
        (Some(file), Some(password)) => {
            // Check if file exists
            if !Path::new(&file).exists() {
                bail!("Input file does not exist: {}", file);
            }
            
            // Infer operation based on file extension
            if file.ends_with(".sec") {
                println!("Detected .sec file - decrypting...");
                decrypt_file(&file, &password)?;
            } else {
                println!("Detected non-.sec file - encrypting...");
                encrypt_file(&file, &password)?;
            }
        },
        _ => {
            // No arguments provided, start interactive mode
            interactive_mode()?;
        }
    }
    
    Ok(())
}
