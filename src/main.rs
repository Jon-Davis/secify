use std::path::Path;
use anyhow::{Result, bail};
use clap::Parser;

use secify::*;

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
                println!("Using encryption algorithm: {}", cli.algorithm.to_string());
                encrypt_file(&file, &password, &cli.algorithm)?;
            }
        },
        _ => {
            // No arguments provided, start interactive mode
            interactive_mode()?;
        }
    }
    
    Ok(())
}
