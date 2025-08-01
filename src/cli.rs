use clap::Parser;
use crate::crypto::{EncryptionAlgorithm, parse_algorithm};

#[derive(Parser)]
#[command(name = "secify")]
#[command(about = "A CLI tool for encrypting and decrypting files and directories using industry-standard cryptography (AES-256-GCM, ChaCha20-Poly1305) with Argon2 key derivation")]
pub struct Cli {
    /// Input file or directory path (.sec files will be decrypted, others will be encrypted)
    pub file: Option<String>,
    /// Password for encryption/decryption
    #[arg(short, long)]
    pub password: Option<String>,
    /// Encryption algorithm (aes256, chacha20, xchacha20, default: xchacha20)
    #[arg(short, long, value_parser = parse_algorithm, default_value = "xchacha20")]
    pub algorithm: EncryptionAlgorithm,
}

pub const DEFAULT_ALGORITHM: EncryptionAlgorithm = EncryptionAlgorithm::XChaCha20Poly1305;
pub const MIN_PASSWORD_LENGTH: usize = 8; // Increased for better security
