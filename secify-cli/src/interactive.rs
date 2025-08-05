use std::fs;
use std::path::Path;
use std::io::{self, Write};
use anyhow::{Result, Context, bail};

use secify_lib::{EncryptionAlgorithm, Argon2Params, CompressionAlgorithm, RuntimeCompressionConfig};
use secify_lib::crypto::{StandardKdfConfig, kdf_from_standard};
use crate::cli::{DEFAULT_ALGORITHM, MIN_PASSWORD_LENGTH};
use crate::progress::{encrypt_with_ui, decrypt_with_ui};

pub fn prompt_user(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush().context("Failed to flush stdout")?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)
        .context("Failed to read user input")?;
    
    Ok(input.trim().to_string())
}

pub fn get_password(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush().context("Failed to flush stdout")?;
    
    let password = rpassword::read_password()
        .context("Failed to read password securely")?;
    
    if password.is_empty() {
        bail!("Password cannot be empty");
    }
    
    Ok(password)
}

pub fn list_current_directory() -> Result<()> {
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
            dirs.push(format!("{name}/"));
        } else {
            files.push(name);
        }
    }
    
    // Sort and display directories first, then files
    dirs.sort();
    files.sort();
    
    for dir in dirs {
        println!("  📁 {dir}");
    }
    for file in files {
        println!("  📄 {file}");
    }
    println!();
    
    Ok(())
}

pub fn interactive_mode_with_params(mut argon2_params: Argon2Params) -> Result<()> {
    println!("=== Secify Interactive Mode ===\n");
    
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
            println!("File or directory '{path}' does not exist. Please check the path.");
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
    
    // Get encryption algorithm (only for encryption)
    let algorithm = if is_decrypt {
        DEFAULT_ALGORITHM // Will be read from file header
    } else {
        println!("\nSelect encryption algorithm:");
        println!("1. AES-256-GCM (hardware accelerated on most CPUs, 96-bit nonce)");
        println!("2. ChaCha20-Poly1305 (faster on mobile/older CPUs, 96-bit nonce)");
        println!("3. XChaCha20-Poly1305 (default, recommended for high-volume use, 192-bit nonce)");
        
        loop {
            let choice = prompt_user("Enter choice (1, 2, or 3, default is 3): ")?;
            match choice.trim() {
                "1" => break EncryptionAlgorithm::Aes256Gcm,
                "2" => break EncryptionAlgorithm::ChaCha20Poly1305,
                "" | "3" => break EncryptionAlgorithm::XChaCha20Poly1305,
                _ => println!("Invalid choice. Please enter 1, 2, or 3."),
            }
        }
    };

    // Get Argon2 parameters (only for encryption)
    if !is_decrypt {
        println!("\nArgon2id Key Derivation Settings:");
        println!("Select KDF preset:");
        println!("1. Recommended (2GB memory, 1 iteration, 4 threads) - High security");
        println!("2. Constrained (64MB memory, 3 iterations, 4 threads) - Resource constrained");
        println!("3. Custom - Specify your own parameters");
        
        let kdf_choice = loop {
            let choice = prompt_user("Enter choice (1, 2, or 3, default is 1): ")?;
            match choice.trim() {
                "" | "1" => break StandardKdfConfig::Argon2idRecommended,
                "2" => break StandardKdfConfig::Argon2idConstrained,
                "3" => break StandardKdfConfig::UnknownKdf, // Custom
                _ => println!("Invalid choice. Please enter 1, 2, or 3."),
            }
        };
        
        argon2_params = match kdf_choice {
            StandardKdfConfig::Argon2idRecommended => {
                println!("Using recommended preset: 2GB memory, 1 iteration, 4 threads");
                kdf_from_standard(StandardKdfConfig::Argon2idRecommended)
                    .map_err(|e| anyhow::anyhow!("Failed to create recommended preset: {}", e))?
            },
            StandardKdfConfig::Argon2idConstrained => {
                println!("Using constrained preset: 64MB memory, 3 iterations, 4 threads");
                kdf_from_standard(StandardKdfConfig::Argon2idConstrained)
                    .map_err(|e| anyhow::anyhow!("Failed to create constrained preset: {}", e))?
            },
            StandardKdfConfig::UnknownKdf => {
                // Custom parameters
                println!("Current custom settings: {}MB memory, {} iterations, {} threads", 
                         argon2_params.memory_mb, argon2_params.time_cost, argon2_params.parallelism);
                
                let customize = prompt_user("Customize these parameters? (y/N): ")?;
                if customize.to_lowercase() == "y" || customize.to_lowercase() == "yes" {
                    println!("Memory size in MB (current: {}): ", argon2_params.memory_mb);
                    let memory_input = prompt_user("")?;
                    if !memory_input.trim().is_empty() {
                        argon2_params.memory_mb = memory_input.trim().parse()
                            .map_err(|_| anyhow::anyhow!("Invalid memory size"))?;
                    }
                    
                    println!("Number of iterations (current: {}): ", argon2_params.time_cost);
                    let time_input = prompt_user("")?;
                    if !time_input.trim().is_empty() {
                        argon2_params.time_cost = time_input.trim().parse()
                            .map_err(|_| anyhow::anyhow!("Invalid time cost"))?;
                    }
                    
                    println!("Number of threads (current: {}): ", argon2_params.parallelism);
                    let parallelism_input = prompt_user("")?;
                    if !parallelism_input.trim().is_empty() {
                        argon2_params.parallelism = parallelism_input.trim().parse()
                            .map_err(|_| anyhow::anyhow!("Invalid parallelism"))?;
                    }
                }
                argon2_params
            }
        };
    }

    // Get compression settings (only for encryption)
    let compression_config = if !is_decrypt {
        println!("\nCompression Settings:");
        println!("Select compression algorithm:");
        println!("1. None (faster encryption, larger files)");
        println!("2. Zstandard (zstd) (slower encryption, smaller files, default)");
        
        let compression_alg = loop {
            let choice = prompt_user("Enter choice (1 or 2, default is 2): ")?;
            match choice.trim() {
                "1" => break CompressionAlgorithm::None,
                "" | "2" => break CompressionAlgorithm::Zstd,
                _ => println!("Invalid choice. Please enter 1 or 2."),
            }
        };
        
        if matches!(compression_alg, CompressionAlgorithm::Zstd) {
            println!("\nZstandard Compression Level:");
            println!("1-3: Fast compression (lower CPU usage)");
            println!("4-6: Balanced compression (default: 3)");
            println!("7-12: Good compression (higher CPU usage)");
            println!("13-19: High compression (much slower)");
            println!("20-22: Maximum compression (very slow)");
            
            let compression_level = loop {
                let input = prompt_user("Enter compression level (1-22, default: 3): ")?;
                if input.is_empty() {
                    break 3; // Default level
                }
                match input.parse::<i32>() {
                    Ok(level) if level >= 1 && level <= 22 => break level,
                    Ok(_) => println!("Compression level must be between 1 and 22."),
                    Err(_) => println!("Invalid number. Please enter a value between 1 and 22."),
                }
            };
            
            Some(RuntimeCompressionConfig {
                algorithm: compression_alg.to_string().to_owned(),
                level: compression_level,
            })
        } else {
            None
        }
    } else {
        None
    };
    
    // Get password
    let password = loop {
        let pass = get_password(&format!("Enter password for {}: ", if is_decrypt { "decryption" } else { "encryption" }))?;
        if pass.is_empty() {
            println!("Password cannot be empty.");
            continue;
        }
        if !is_decrypt {
            // Only require password validation for encryption
            if pass.len() < MIN_PASSWORD_LENGTH {
                println!("Password must be at least {MIN_PASSWORD_LENGTH} characters long for security.");
                continue;
            }
            
            // Check for basic password strength
            let has_upper = pass.chars().any(|c| c.is_uppercase());
            let has_lower = pass.chars().any(|c| c.is_lowercase());
            let has_digit = pass.chars().any(|c| c.is_numeric());
            
            if !has_upper || !has_lower || !has_digit {
                println!("Warning: Password should contain uppercase, lowercase, and numeric characters for better security.");
                let continue_anyway = prompt_user("Continue anyway? (y/N): ")?;
                if continue_anyway.to_lowercase() != "y" && continue_anyway.to_lowercase() != "yes" {
                    continue;
                }
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
        // Determine output path (remove .sec extension)
        let output_path = &file_path[..file_path.len() - 4];
        decrypt_with_ui(&file_path, output_path, &password)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
    } else {
        println!("\nEncrypting file...");
        // Create output path
        let clean_path = file_path.trim_end_matches('/').trim_end_matches('\\');
        let output_path = format!("{clean_path}.sec");
        encrypt_with_ui(&file_path, &output_path, &password, &algorithm, &argon2_params, compression_config)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
    }
    
    Ok(())
}