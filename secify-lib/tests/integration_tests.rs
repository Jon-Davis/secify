use std::fs;
use std::path::Path;
use tempfile::TempDir;
use secify_lib::{encrypt_core, decrypt_core, EncryptionAlgorithm, Argon2Params};

/// Integration tests for end-to-end encryption/decryption workflows
/// These tests exercise the complete application flow

const TEST_PASSWORD: &str = "IntegrationTestPassword123!";

fn create_test_params() -> Argon2Params {
    // Fast parameters for integration testing
    Argon2Params::new(8, 1, 1).unwrap()
}

#[test]
fn test_complete_file_encryption_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    let test_content = b"This is a complete integration test for file encryption and decryption.";
    
    // Create test file
    fs::write(&test_file, test_content).unwrap();
    
    // Test with all supported algorithms
    let algorithms = [
        EncryptionAlgorithm::Aes256Gcm,
        EncryptionAlgorithm::ChaCha20Poly1305,
        EncryptionAlgorithm::XChaCha20Poly1305,
    ];
    
    for algorithm in algorithms {
        println!("Testing complete workflow with {:?}", algorithm);
        
        let params = create_test_params();
        let file_path = test_file.to_str().unwrap();
        
        // Step 1: Encrypt the file
        let encrypted_path = format!("{}.sec", file_path);
        encrypt_core(
            file_path,
            &encrypted_path,
            TEST_PASSWORD,
            &algorithm,
            &params,
            None, // No compression
            None, // No event callback
        ).unwrap();
        
        // Verify encrypted file exists
        assert!(Path::new(&encrypted_path).exists());
        
        // Verify encrypted file is different from original
        let encrypted_data = fs::read(&encrypted_path).unwrap();
        assert_ne!(encrypted_data, test_content);
        assert!(encrypted_data.len() > test_content.len());
        
        // Step 2: Remove original file
        fs::remove_file(&test_file).unwrap();
        assert!(!test_file.exists());
        
        // Step 3: Decrypt the file
        let decrypted_path = file_path;
        decrypt_core(
            &encrypted_path,
            decrypted_path,
            TEST_PASSWORD,
            None, // No event callback
        ).unwrap();
        
        // Step 4: Verify restored file
        assert!(test_file.exists());
        let restored_content = fs::read(&test_file).unwrap();
        assert_eq!(restored_content, test_content);
        
        // Cleanup for next iteration
        fs::remove_file(&encrypted_path).unwrap();
    }
}

#[test]
fn test_directory_encryption_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let test_dir = temp_dir.path().join("test_directory");
    fs::create_dir(&test_dir).unwrap();
    
    // Create test directory structure
    fs::write(test_dir.join("file1.txt"), b"Content of file 1").unwrap();
    fs::write(test_dir.join("file2.txt"), b"Content of file 2").unwrap();
    
    let subdir = test_dir.join("subdir");
    fs::create_dir(&subdir).unwrap();
    fs::write(subdir.join("file3.txt"), b"Content of file 3 in subdirectory").unwrap();
    
    let algorithm = EncryptionAlgorithm::Aes256Gcm;
    let params = create_test_params();
    let dir_path = test_dir.to_str().unwrap();
    
    // Step 1: Encrypt the directory
    let encrypted_path = format!("{}.sec", dir_path);
    encrypt_core(
        dir_path,
        &encrypted_path,
        TEST_PASSWORD,
        &algorithm,
        &params,
        None, // No compression
        None, // No event callback
    ).unwrap();
    
    // Verify encrypted file exists
    assert!(Path::new(&encrypted_path).exists());
    
    // Step 2: Remove original directory
    fs::remove_dir_all(&test_dir).unwrap();
    assert!(!test_dir.exists());
    
    // Step 3: Decrypt the directory
    decrypt_core(
        &encrypted_path,
        dir_path,
        TEST_PASSWORD,
        None, // No event callback
    ).unwrap();
    
    // Step 4: Verify restored directory structure
    assert!(test_dir.exists());
    assert!(test_dir.is_dir());
    
    // Check individual files
    assert_eq!(fs::read_to_string(test_dir.join("file1.txt")).unwrap(), "Content of file 1");
    assert_eq!(fs::read_to_string(test_dir.join("file2.txt")).unwrap(), "Content of file 2");
    assert_eq!(fs::read_to_string(subdir.join("file3.txt")).unwrap(), "Content of file 3 in subdirectory");
}

#[test]
fn test_wrong_password_rejection() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    let test_content = b"This file should not be decryptable with wrong password.";
    
    fs::write(&test_file, test_content).unwrap();
    
    let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
    let params = create_test_params();
    let file_path = test_file.to_str().unwrap();
    
    // Encrypt with correct password
    let encrypted_path = format!("{}.sec", file_path);
    encrypt_core(
        file_path,
        &encrypted_path,
        TEST_PASSWORD,
        &algorithm,
        &params,
        None, // No compression
        None, // No event callback
    ).unwrap();
    
    fs::remove_file(&test_file).unwrap();
    
    // Try to decrypt with wrong password
    let result = decrypt_core(
        &encrypted_path,
        file_path,
        "WrongPassword123!",
        None, // No event callback
    );
    assert!(result.is_err());
    
    // Original file should not be restored
    assert!(!test_file.exists());
    
    // But correct password should still work
    decrypt_core(
        &encrypted_path,
        file_path,
        TEST_PASSWORD,
        None, // No event callback
    ).unwrap();
    assert!(test_file.exists());
    
    let restored_content = fs::read(&test_file).unwrap();
    assert_eq!(restored_content, test_content);
}

#[test]
fn test_corrupted_file_detection() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    let test_content = b"This file will be corrupted to test integrity checking.";
    
    fs::write(&test_file, test_content).unwrap();
    
    let algorithm = EncryptionAlgorithm::XChaCha20Poly1305;
    let params = create_test_params();
    let file_path = test_file.to_str().unwrap();
    
    // Encrypt the file
    let encrypted_path = format!("{}.sec", file_path);
    encrypt_core(
        file_path,
        &encrypted_path,
        TEST_PASSWORD,
        &algorithm,
        &params,
        None, // No compression
        None, // No event callback
    ).unwrap();
    
    fs::remove_file(&test_file).unwrap();
    
    // Corrupt the encrypted file by modifying a byte in the middle
    let mut encrypted_data = fs::read(&encrypted_path).unwrap();
    let corruption_offset = encrypted_data.len() / 2;
    encrypted_data[corruption_offset] ^= 0x01; // Flip one bit
    fs::write(&encrypted_path, &encrypted_data).unwrap();
    
    // Try to decrypt corrupted file (should fail due to integrity check)
    let result = decrypt_core(
        &encrypted_path,
        file_path,
        TEST_PASSWORD,
        None, // No event callback
    );
    assert!(result.is_err());
    
    // Original file should not be created
    assert!(!test_file.exists());
}

#[test]
fn test_large_file_streaming() {
    let temp_dir = TempDir::new().unwrap();
    let large_file = temp_dir.path().join("large_test.bin");
    
    // Create a 5MB file to test streaming capabilities
    let large_content = vec![0x42u8; 5 * 1024 * 1024];
    fs::write(&large_file, &large_content).unwrap();
    
    let algorithm = EncryptionAlgorithm::Aes256Gcm;
    let params = create_test_params();
    let file_path = large_file.to_str().unwrap();
    
    println!("Testing large file streaming encryption...");
    
    // Encrypt large file
    let encrypted_path = format!("{}.sec", file_path);
    encrypt_core(
        file_path,
        &encrypted_path,
        TEST_PASSWORD,
        &algorithm,
        &params,
        None, // No compression
        None, // No event callback
    ).unwrap();
    
    assert!(Path::new(&encrypted_path).exists());
    
    // Verify encrypted file is larger than original
    let encrypted_size = fs::metadata(&encrypted_path).unwrap().len();
    assert!(encrypted_size > large_content.len() as u64);
    
    // Remove original
    fs::remove_file(&large_file).unwrap();
    
    println!("Testing large file streaming decryption...");
    
    // Decrypt large file
    decrypt_core(
        &encrypted_path,
        file_path,
        TEST_PASSWORD,
        None, // No event callback
    ).unwrap();
    
    // Verify restored file
    assert!(large_file.exists());
    let restored_content = fs::read(&large_file).unwrap();
    assert_eq!(restored_content, large_content);
}

#[test]
fn test_empty_file_handling() {
    let temp_dir = TempDir::new().unwrap();
    let empty_file = temp_dir.path().join("empty.txt");
    
    // Create empty file
    fs::write(&empty_file, b"").unwrap();
    
    let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
    let params = create_test_params();
    let file_path = empty_file.to_str().unwrap();
    
    // Encrypt empty file
    let encrypted_path = format!("{}.sec", file_path);
    encrypt_core(
        file_path,
        &encrypted_path,
        TEST_PASSWORD,
        &algorithm,
        &params,
        None, // No compression
        None, // No event callback
    ).unwrap();
    
    assert!(Path::new(&encrypted_path).exists());
    
    // Encrypted file should not be empty (contains headers, metadata, etc.)
    let encrypted_size = fs::metadata(&encrypted_path).unwrap().len();
    assert!(encrypted_size > 0);
    
    // Remove original
    fs::remove_file(&empty_file).unwrap();
    
    // Decrypt empty file
    decrypt_core(
        &encrypted_path,
        file_path,
        TEST_PASSWORD,
        None, // No event callback
    ).unwrap();
    
    // Verify restored empty file
    assert!(empty_file.exists());
    let restored_content = fs::read(&empty_file).unwrap();
    assert!(restored_content.is_empty());
}

#[test]
fn test_unicode_filename_handling() {
    let temp_dir = TempDir::new().unwrap();
    let unicode_file = temp_dir.path().join("тест_файл_🔒.txt");
    let test_content = b"Unicode filename test content";
    
    fs::write(&unicode_file, test_content).unwrap();
    
    let algorithm = EncryptionAlgorithm::XChaCha20Poly1305;
    let params = create_test_params();
    let file_path = unicode_file.to_str().unwrap();
    
    // Encrypt file with unicode name
    let encrypted_path = format!("{}.sec", file_path);
    encrypt_core(
        file_path,
        &encrypted_path,
        TEST_PASSWORD,
        &algorithm,
        &params,
        None, // No compression
        None, // No event callback
    ).unwrap();
    
    assert!(Path::new(&encrypted_path).exists());
    
    // Remove original
    fs::remove_file(&unicode_file).unwrap();
    
    // Decrypt file with unicode name
    decrypt_core(
        &encrypted_path,
        file_path,
        TEST_PASSWORD,
        None, // No event callback
    ).unwrap();
    
    // Verify restored file
    assert!(unicode_file.exists());
    let restored_content = fs::read(&unicode_file).unwrap();
    assert_eq!(restored_content, test_content);
}

#[test]
fn test_multiple_encryption_rounds() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("multi_round.txt");
    let original_content = b"This file will be encrypted multiple times to test robustness.";
    
    fs::write(&test_file, original_content).unwrap();
    
    let algorithm = EncryptionAlgorithm::Aes256Gcm;
    let params = create_test_params();
    let file_path = test_file.to_str().unwrap();
    
    // Perform multiple encryption/decryption rounds
    for round in 1..=3 {
        println!("Encryption round {}", round);
        
        // Encrypt
        let encrypted_path = format!("{}.sec", file_path);
        encrypt_core(
            file_path,
            &encrypted_path,
            TEST_PASSWORD,
            &algorithm,
            &params,
            None, // No compression
            None, // No event callback
        ).unwrap();
        
        assert!(Path::new(&encrypted_path).exists());
        
        // Remove original
        fs::remove_file(&test_file).unwrap();
        
        // Decrypt
        decrypt_core(
            &encrypted_path,
            file_path,
            TEST_PASSWORD,
            None, // No event callback
        ).unwrap();
        
        // Verify content is still intact
        assert!(test_file.exists());
        let content = fs::read(&test_file).unwrap();
        assert_eq!(content, original_content);
        
        // Cleanup encrypted file
        fs::remove_file(&encrypted_path).unwrap();
    }
}
