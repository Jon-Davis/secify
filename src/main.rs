use std::fs;
use std::path::Path;
use std::io::{self, Write};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{rand_core::RngCore, SaltString};
use clap::{Parser, Subcommand};
use anyhow::{Result, Context, bail};
use zip::{ZipWriter, ZipArchive, write::FileOptions, CompressionMethod};
use std::io::Cursor;
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Parser)]
#[command(name = "aesify")]
#[command(about = "A CLI tool for encrypting and decrypting files and directories using AES-256-GCM with Argon2 key derivation")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file or directory
    Encrypt {
        /// Input file or directory path
        #[arg(short, long)]
        file: String,
        /// Password for encryption
        #[arg(short, long)]
        password: String,
    },
    /// Decrypt a file
    Decrypt {
        /// Input .aes file path
        #[arg(short, long)]
        file: String,
        /// Password for decryption
        #[arg(short, long)]
        password: String,
    },
}

const SALT_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const KEY_LENGTH: usize = 32;

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LENGTH]> {
    let argon2 = Argon2::default();
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| anyhow::anyhow!("Failed to encode salt: {}", e))?;
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
    
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
    
    // Determine what we're encrypting
    let (input_data, is_directory) = if path.is_dir() {
        println!("Zipping directory before encryption...");
        let zip_data = zip_directory(path)?;
        (zip_data, true)
    } else {
        // Read the input file
        let file_data = fs::read(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path))?;
        (file_data, false)
    };
    
    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LENGTH];
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);
    
    // Derive encryption key from password and salt
    let key = derive_key(password, &salt)?;
    
    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;
    
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt the data
    let ciphertext = cipher.encrypt(nonce, input_data.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to encrypt data: {}", e))?;
    
    // Create output file structure: 
    // 1 byte: directory flag (1 for directory, 0 for file)
    // 32 bytes: salt
    // 12 bytes: nonce
    // remaining: ciphertext
    let mut output_data = Vec::new();
    output_data.push(if is_directory { 1u8 } else { 0u8 });
    output_data.extend_from_slice(&salt);
    output_data.extend_from_slice(&nonce_bytes);
    output_data.extend_from_slice(&ciphertext);
    
    // Write to .aes file
    // Remove trailing path separators before adding .aes extension
    let clean_path = file_path.trim_end_matches('/').trim_end_matches('\\');
    let output_path = format!("{}.aes", clean_path);
    fs::write(&output_path, output_data)
        .with_context(|| format!("Failed to write encrypted file: {}", output_path))?;
    
    if is_directory {
        println!("Directory zipped and encrypted successfully: {}", output_path);
    } else {
        println!("File encrypted successfully: {}", output_path);
    }
    Ok(())
}

fn decrypt_file(file_path: &str, password: &str) -> Result<()> {
    // Ensure the file has .aes extension
    if !file_path.ends_with(".aes") {
        bail!("File must have .aes extension");
    }
    
    // Read the encrypted file
    let encrypted_data = fs::read(file_path)
        .with_context(|| format!("Failed to read encrypted file: {}", file_path))?;
    
    // Check minimum file size (flag + salt + nonce + at least some ciphertext)
    if encrypted_data.len() < 1 + SALT_LENGTH + NONCE_LENGTH + 16 {
        bail!("Invalid encrypted file format");
    }
    
    // Extract directory flag, salt, nonce, and ciphertext
    let is_directory = encrypted_data[0] == 1u8;
    let salt = &encrypted_data[1..1 + SALT_LENGTH];
    let nonce_bytes = &encrypted_data[1 + SALT_LENGTH..1 + SALT_LENGTH + NONCE_LENGTH];
    let ciphertext = &encrypted_data[1 + SALT_LENGTH + NONCE_LENGTH..];
    
    // Derive decryption key from password and salt
    let key = derive_key(password, salt)?;
    
    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;
    
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Decrypt the data
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt data - incorrect password or corrupted file: {}", e))?;
    
    // Determine output path (remove .aes extension)
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
        
        // Write decrypted data
        fs::write(output_path, plaintext)
            .with_context(|| format!("Failed to write decrypted file: {}", output_path))?;
        
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
    
    // Ask for operation
    loop {
        let operation = prompt_user("Do you want to (e)ncrypt or (d)ecrypt a file? [e/d]: ")?;
        let operation = operation.to_lowercase();
        
        match operation.as_str() {
            "e" | "encrypt" => {
                return interactive_encrypt();
            },
            "d" | "decrypt" => {
                return interactive_decrypt();
            },
            _ => {
                println!("Please enter 'e' for encrypt or 'd' for decrypt.");
                continue;
            }
        }
    }
}

fn interactive_encrypt() -> Result<()> {
    // Get file path
    let file_path = loop {
        let path = prompt_user("Enter the file or directory path to encrypt (type 'ls' to list files): ")?;
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
    
    // Get password
    let password = loop {
        let pass = get_password("Enter password for encryption: ")?;
        if pass.is_empty() {
            println!("Password cannot be empty.");
            continue;
        }
        if pass.len() < 4 {
            println!("Password should be at least 4 characters long for security.");
            continue;
        }
        
        let confirm = get_password("Confirm password: ")?;
        if pass != confirm {
            println!("Passwords do not match. Please try again.");
            continue;
        }
        break pass;
    };
    
    println!("\nEncrypting file...");
    encrypt_file(&file_path, &password)?;
    
    Ok(())
}

fn interactive_decrypt() -> Result<()> {
    // Get file path
    let file_path = loop {
        let path = prompt_user("Enter the .aes file path to decrypt (type 'ls' to list files): ")?;
        if path.is_empty() {
            println!("File path cannot be empty.");
            continue;
        }
        if path.to_lowercase() == "ls" || path.to_lowercase() == "dir" {
            list_current_directory()?;
            continue;
        }
        if !path.ends_with(".aes") {
            println!("File must have .aes extension.");
            continue;
        }
        if !Path::new(&path).exists() {
            println!("File '{}' does not exist. Please check the path.", path);
            continue;
        }
        break path;
    };
    
    // Get password
    let password = loop {
        let pass = get_password("Enter password for decryption: ")?;
        if pass.is_empty() {
            println!("Password cannot be empty.");
            continue;
        }
        break pass;
    };
    
    println!("\nDecrypting file...");
    decrypt_file(&file_path, &password)?;
    
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match &cli.command {
        Some(Commands::Encrypt { file, password }) => {
            if !Path::new(file).exists() {
                bail!("Input file or directory does not exist: {}", file);
            }
            encrypt_file(file, password)?;
        },
        Some(Commands::Decrypt { file, password }) => {
            if !Path::new(file).exists() {
                bail!("Input file does not exist: {}", file);
            }
            decrypt_file(file, password)?;
        },
        None => {
            // No command provided, start interactive mode
            interactive_mode()?;
        }
    }
    
    Ok(())
}
