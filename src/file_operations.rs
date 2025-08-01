use std::path::Path;
use anyhow::{Result, bail};

use crate::crypto::*;
use crate::streaming::{stream_encrypt_tar, stream_decrypt_tar};

pub fn encrypt_file(file_path: &str, password: &str, algorithm: &EncryptionAlgorithm, argon2_params: &Argon2Params) -> Result<()> {
    let path = Path::new(file_path);
    
    // Validate file/directory exists
    if !path.exists() {
        bail!("File or directory does not exist: {}", file_path);
    }
    
    // Always use TAR format for both files and directories
    println!("Using TAR archive format with full streaming pipeline (read→tar→encrypt→write)");
    let clean_path = file_path.trim_end_matches('/').trim_end_matches('\\');
    let output_path = format!("{clean_path}.sec");
    
    // Use streaming TAR encryption for everything
    stream_encrypt_tar(file_path, &output_path, password, algorithm, argon2_params)
}

pub fn decrypt_file(file_path: &str, password: &str) -> Result<()> {
    // Ensure the file has .sec extension
    if !file_path.ends_with(".sec") {
        bail!("File must have .sec extension");
    }
    
    // Everything is now TAR archive format - use streaming TAR decryption
    println!("TAR archive detected - using streaming decryption");
    
    // Determine output path (remove .sec extension)
    let output_path = &file_path[..file_path.len() - 4];
    
    stream_decrypt_tar(file_path, output_path, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    
    const TEST_PASSWORD: &str = "TestPassword123!";
    const TEST_DATA: &[u8] = b"Test file content for file operations testing.";
    
    fn create_test_argon2_params() -> Argon2Params {
        Argon2Params::new(8, 1, 1).unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_file_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test_input.txt");
        
        // Create test input file
        fs::write(&input_file, TEST_DATA).unwrap();
        let input_path = input_file.to_str().unwrap();
        
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let params = create_test_argon2_params();
        
        // Test encrypt_file function
        encrypt_file(input_path, TEST_PASSWORD, &algorithm, &params).unwrap();
        
        // Verify .sec file was created
        let encrypted_path = format!("{}.sec", input_path);
        assert!(Path::new(&encrypted_path).exists());
        
        // Remove original file to test decryption
        fs::remove_file(&input_file).unwrap();
        assert!(!input_file.exists());
        
        // Test decrypt_file function
        decrypt_file(&encrypted_path, TEST_PASSWORD).unwrap();
        
        // Verify original file was recreated with correct content
        assert!(input_file.exists());
        let decrypted_data = fs::read(&input_file).unwrap();
        assert_eq!(decrypted_data, TEST_DATA);
    }

    #[test]
    fn test_encrypt_file_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent_file = temp_dir.path().join("nonexistent.txt");
        
        let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
        let params = create_test_argon2_params();
        
        let result = encrypt_file(
            nonexistent_file.to_str().unwrap(),
            TEST_PASSWORD,
            &algorithm,
            &params,
        );
        
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_file_wrong_extension() {
        let temp_dir = TempDir::new().unwrap();
        let wrong_ext_file = temp_dir.path().join("test.txt");
        
        fs::write(&wrong_ext_file, b"dummy content").unwrap();
        
        let result = decrypt_file(wrong_ext_file.to_str().unwrap(), TEST_PASSWORD);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_file_wrong_password() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("test_input.txt");
        
        fs::write(&input_file, TEST_DATA).unwrap();
        let input_path = input_file.to_str().unwrap();
        
        let algorithm = EncryptionAlgorithm::XChaCha20Poly1305;
        let params = create_test_argon2_params();
        
        // Encrypt with correct password
        encrypt_file(input_path, TEST_PASSWORD, &algorithm, &params).unwrap();
        
        let encrypted_path = format!("{}.sec", input_path);
        
        // Try to decrypt with wrong password
        let result = decrypt_file(&encrypted_path, "WrongPassword");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_all_algorithms() {
        let algorithms = [
            EncryptionAlgorithm::Aes256Gcm,
            EncryptionAlgorithm::ChaCha20Poly1305,
            EncryptionAlgorithm::XChaCha20Poly1305,
        ];
        
        for algorithm in &algorithms {
            let temp_dir = TempDir::new().unwrap();
            let input_file = temp_dir.path().join("test_input.txt");
            
            fs::write(&input_file, TEST_DATA).unwrap();
            let input_path = input_file.to_str().unwrap();
            
            let params = create_test_argon2_params();
            
            // Test encryption with each algorithm
            encrypt_file(input_path, TEST_PASSWORD, algorithm, &params).unwrap();
            
            let encrypted_path = format!("{}.sec", input_path);
            assert!(Path::new(&encrypted_path).exists());
            
            // Remove original and decrypt
            fs::remove_file(&input_file).unwrap();
            decrypt_file(&encrypted_path, TEST_PASSWORD).unwrap();
            
            // Verify content
            let decrypted_data = fs::read(&input_file).unwrap();
            assert_eq!(decrypted_data, TEST_DATA, "Failed for algorithm: {:?}", algorithm);
        }
    }

    #[test]
    fn test_encrypt_decrypt_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("empty.txt");
        
        // Create empty file
        fs::write(&input_file, b"").unwrap();
        let input_path = input_file.to_str().unwrap();
        
        let algorithm = EncryptionAlgorithm::Aes256Gcm;
        let params = create_test_argon2_params();
        
        // Test encryption of empty file
        encrypt_file(input_path, TEST_PASSWORD, &algorithm, &params).unwrap();
        
        let encrypted_path = format!("{}.sec", input_path);
        assert!(Path::new(&encrypted_path).exists());
        
        // Encrypted file should be larger than empty due to headers/metadata
        let encrypted_data = fs::read(&encrypted_path).unwrap();
        assert!(!encrypted_data.is_empty());
        
        // Remove original and decrypt
        fs::remove_file(&input_file).unwrap();
        decrypt_file(&encrypted_path, TEST_PASSWORD).unwrap();
        
        // Verify empty file was recreated
        assert!(input_file.exists());
        let decrypted_data = fs::read(&input_file).unwrap();
        assert!(decrypted_data.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_large_file() {
        let temp_dir = TempDir::new().unwrap();
        let input_file = temp_dir.path().join("large.txt");
        
        // Create a larger file (1MB) to test streaming
        let large_data = vec![0x42u8; 1024 * 1024];
        fs::write(&input_file, &large_data).unwrap();
        let input_path = input_file.to_str().unwrap();
        
        let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
        let params = create_test_argon2_params();
        
        // Test encryption of large file
        encrypt_file(input_path, TEST_PASSWORD, &algorithm, &params).unwrap();
        
        let encrypted_path = format!("{}.sec", input_path);
        assert!(Path::new(&encrypted_path).exists());
        
        // Remove original and decrypt
        fs::remove_file(&input_file).unwrap();
        decrypt_file(&encrypted_path, TEST_PASSWORD).unwrap();
        
        // Verify large file content
        assert!(input_file.exists());
        let decrypted_data = fs::read(&input_file).unwrap();
        assert_eq!(decrypted_data, large_data);
    }
}
