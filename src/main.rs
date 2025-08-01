use std::path::Path;
use anyhow::{Result, bail};
use clap::Parser;

use secify::*;

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Create Argon2 parameters from CLI arguments
    let argon2_params = crypto::Argon2Params::new(cli.memory_mb, cli.time_cost, cli.parallelism)?;
    
    match (cli.file, cli.password) {
        (Some(file), Some(password)) => {
            // Check if file exists
            if !Path::new(&file).exists() {
                bail!("Input file does not exist: {}", file);
            }
            
            // Infer operation based on file extension
            if file.ends_with(".sec") {
                println!("Detected .sec file - decrypting...");
                file_operations::decrypt_file(&file, &password)?;
            } else {
                println!("Detected non-.sec file - encrypting...");
                println!("Using encryption algorithm: {}", cli.algorithm.to_string());
                println!("Using Argon2id parameters: {}MB memory, {} iterations, {} threads", 
                         argon2_params.memory_mb, argon2_params.time_cost, argon2_params.parallelism);
                file_operations::encrypt_file(&file, &password, &cli.algorithm, &argon2_params)?;
            }
        },
        _ => {
            // No arguments provided, start interactive mode
            interactive::interactive_mode_with_params(argon2_params)?;
        }
    }
    
    Ok(())
}
