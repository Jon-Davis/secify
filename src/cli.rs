use clap::Parser;
use crate::crypto::{EncryptionAlgorithm, parse_algorithm, CompressionAlgorithm};

fn parse_compression_algorithm(s: &str) -> Result<CompressionAlgorithm, String> {
    CompressionAlgorithm::from_string(s).map_err(|e| e.to_string())
}

#[derive(Parser)]
#[command(name = "secify")]
#[command(about = "A CLI tool for encrypting and decrypting files and directories using industry-standard cryptography")]
#[command(long_about = "Secify is a secure file encryption program that protects your files using AES-256-GCM, ChaCha20-Poly1305, or XChaCha20-Poly1305 encryption with Argon2id key derivation. You can customize the Argon2 parameters for different security/performance trade-offs.")]
pub struct Cli {
    /// Input file or directory path (.sec files will be decrypted, others will be encrypted)
    pub file: Option<String>,
    /// Password for encryption/decryption
    #[arg(short, long)]
    pub password: Option<String>,
    /// Encryption algorithm (aes256, chacha20, xchacha20, default: xchacha20)
    #[arg(short, long, value_parser = parse_algorithm, default_value = "xchacha20")]
    pub algorithm: EncryptionAlgorithm,
    /// Optional compression algorithm (none, zstd, default: zstd)
    #[arg(short, long, value_parser = parse_compression_algorithm, default_value = "zstd")]
    pub compression: CompressionAlgorithm,
    /// Compression level (1-22 for zstd, default: 3). Higher values are slower but compress better.
    #[arg(long, default_value = "3", help = "Compression level (1-22 for zstd, default: 3)")]
    pub compression_level: i32,
    /// Argon2 memory cost in MB (8-2048, default: 128). Higher values are more secure but slower.
    #[arg(long, default_value = "128", help = "Argon2 memory cost in MB (8-2048, default: 128)")]
    pub memory_mb: u32,
    /// Argon2 time cost/iterations (1-100, default: 8). Higher values are more secure but slower.
    #[arg(long, default_value = "8", help = "Argon2 time cost/iterations (1-100, default: 8)")]
    pub time_cost: u32,
    /// Argon2 parallelism/threads (1-16, default: 4). Should match your CPU cores.
    #[arg(long, default_value = "4", help = "Argon2 parallelism/threads (1-16, default: 4)")]
    pub parallelism: u32,
}

pub const DEFAULT_ALGORITHM: EncryptionAlgorithm = EncryptionAlgorithm::XChaCha20Poly1305;
pub const MIN_PASSWORD_LENGTH: usize = 8; // Increased for better security
