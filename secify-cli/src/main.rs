use std::path::Path;
use anyhow::{Result, bail};
use clap::Parser;

use secify_lib::{Argon2Params, RuntimeCompressionConfig, CompressionAlgorithm};
use secify_lib::crypto::{StandardKdfConfig, kdf_from_standard};

mod cli;
mod progress;
mod interactive;

use cli::Cli;
use progress::{encrypt_with_ui, decrypt_with_ui};

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Create Argon2 parameters based on preset or custom values
    let argon2_params = match cli.kdf_preset {
        StandardKdfConfig::Argon2idRecommended => {
            kdf_from_standard(StandardKdfConfig::Argon2idRecommended)
                .map_err(|e| anyhow::anyhow!("Failed to create recommended KDF preset: {}", e))?
        },
        StandardKdfConfig::Argon2idConstrained => {
            kdf_from_standard(StandardKdfConfig::Argon2idConstrained)
                .map_err(|e| anyhow::anyhow!("Failed to create constrained KDF preset: {}", e))?
        },
        StandardKdfConfig::UnknownKdf => {
            // Custom parameters
            Argon2Params::new(cli.memory_mb, cli.time_cost, cli.parallelism)?
        },
    };
    
    // Create compression config if compression is enabled
    let compression_config = if matches!(cli.compression, CompressionAlgorithm::None) {
        None
    } else {
        Some(RuntimeCompressionConfig {
            algorithm: cli.compression.to_string().to_owned(),
            level: cli.compression_level,
        })
    };
    
    match cli.file {
        Some(file) => {
            // Check if file exists
            if !Path::new(&file).exists() {
                bail!("Input file does not exist: {}", file);
            }
            
            // Get password from CLI or prompt for it
            let password = match cli.password {
                Some(pass) => pass,
                None => {
                    use std::io::{self, Write};
                    print!("Enter password: ");
                    io::stdout().flush()?;
                    let mut password = String::new();
                    io::stdin().read_line(&mut password)?;
                    password.trim().to_string()
                }
            };
            
            // Infer operation based on file extension
            if file.ends_with(".sec") {
                println!("Detected .sec file - decrypting...");
                println!("TAR archive detected - using streaming decryption");
                
                // Determine output path (remove .sec extension)
                let output_path = &file[..file.len() - 4];
                
                decrypt_with_ui(&file, output_path, &password)
                    .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
            } else {
                println!("Detected non-.sec file - encrypting...");
                println!("Using encryption algorithm: {}", cli.algorithm.to_string());
                
                if let Some(ref comp_config) = compression_config {
                    println!("Using compression: {}", comp_config.algorithm);
                }
                
                println!("Using chunked encryption: {}KB chunks for optimal memory usage", 
                         secify_lib::DEFAULT_CHUNK_SIZE / 1024);
                
                // Show KDF preset info
                let kdf_info = match cli.kdf_preset {
                    StandardKdfConfig::Argon2idRecommended => "recommended preset (2GB, 1 iter, 4 threads)".to_string(),
                    StandardKdfConfig::Argon2idConstrained => "constrained preset (64MB, 3 iters, 4 threads)".to_string(),
                    StandardKdfConfig::UnknownKdf => format!("custom ({}MB, {} iters, {} threads)", 
                                                            argon2_params.memory_mb, argon2_params.time_cost, argon2_params.parallelism),
                };
                println!("Using Argon2id {}", kdf_info);
                
                // Create output path
                let clean_path = file.trim_end_matches('/').trim_end_matches('\\');
                let output_path = format!("{clean_path}.sec");
                
                encrypt_with_ui(&file, &output_path, &password, &cli.algorithm, &argon2_params, compression_config)
                    .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
            }
        },
        None => {
            // No file provided, start interactive mode
            interactive::interactive_mode_with_params(argon2_params)?;
        }
    }
    
    Ok(())
}
