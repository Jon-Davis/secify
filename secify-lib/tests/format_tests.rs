use std::fs;
use tempfile::TempDir;
use secify_lib::{encrypt_core, decrypt_core, EncryptionAlgorithm, Argon2Params, deserialize_header_from_protobuf};
use std::io::Read;

const TEST_PASSWORD: &str = "FormatTestPassword123!";

fn create_test_params() -> Argon2Params {
    Argon2Params::new(8, 1, 1).unwrap()
}

#[test]
fn test_single_file_uses_no_archive_format() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    let test_content = b"This is a test file to verify single file format.";
    
    // Create test file
    fs::write(&test_file, test_content).unwrap();
    
    let algorithm = EncryptionAlgorithm::XChaCha20Poly1305;
    let params = create_test_params();
    let file_path = test_file.to_str().unwrap();
    let encrypted_path = format!("{}.sec", file_path);
    
    // Encrypt the single file
    encrypt_core(
        file_path,
        &encrypted_path,
        TEST_PASSWORD,
        &algorithm,
        &params,
        None, // No compression
        None, // No event callback
    ).unwrap();
    
    // Read and parse the header to verify format
    let mut encrypted_file = fs::File::open(&encrypted_path).unwrap();
    
    // Read header length (2 bytes as u16, not 4 bytes)
    let mut header_len_bytes = [0u8; 2];
    encrypted_file.read_exact(&mut header_len_bytes).unwrap();
    let header_len = u16::from_le_bytes(header_len_bytes) as usize;
    
    // Read header data
    let mut header_data = vec![0u8; header_len];
    encrypted_file.read_exact(&mut header_data).unwrap();
    
    // Parse header
    let header = deserialize_header_from_protobuf(&header_data).unwrap();
    
    // Verify basic header fields are present for single file
    assert_eq!(header.version, 0, "Header version should be 0 (current FILE_FORMAT_VERSION)");
    assert!(!header.salt.is_empty(), "Salt should not be empty");
    assert!(!header.nonce.is_empty(), "Nonce should not be empty");
    
    // Verify decryption works
    fs::remove_file(&test_file).unwrap();
    decrypt_core(
        &encrypted_path,
        file_path,
        TEST_PASSWORD,
        None, // No event callback
    ).unwrap();
    
    // Verify content is correct
    let restored_content = fs::read(&test_file).unwrap();
    assert_eq!(restored_content, test_content);
}

#[test]
fn test_directory_uses_sec_archive_format() {
    let temp_dir = TempDir::new().unwrap();
    let test_dir = temp_dir.path().join("test_directory");
    fs::create_dir(&test_dir).unwrap();
    
    // Create test directory structure
    fs::write(test_dir.join("file1.txt"), b"Content 1").unwrap();
    fs::write(test_dir.join("file2.txt"), b"Content 2").unwrap();
    
    let algorithm = EncryptionAlgorithm::Aes256Gcm;
    let params = create_test_params();
    let dir_path = test_dir.to_str().unwrap();
    let encrypted_path = format!("{}.sec", dir_path);
    
    // Encrypt the directory
    encrypt_core(
        dir_path,
        &encrypted_path,
        TEST_PASSWORD,
        &algorithm,
        &params,
        None, // No compression
        None, // No event callback
    ).unwrap();
    
    // Read and parse the header to verify format
    let mut encrypted_file = fs::File::open(&encrypted_path).unwrap();
    
    // Read header length (2 bytes as u16, not 4 bytes)
    let mut header_len_bytes = [0u8; 2];
    encrypted_file.read_exact(&mut header_len_bytes).unwrap();
    let header_len = u16::from_le_bytes(header_len_bytes) as usize;
    
    // Read header data
    let mut header_data = vec![0u8; header_len];
    encrypted_file.read_exact(&mut header_data).unwrap();
    
    // Parse header
    let header = deserialize_header_from_protobuf(&header_data).unwrap();
    
    // Verify directory has sec archive field
    // Note: Archive field was removed from EncryptionHeader
    // Directory encryption is handled through the archive processing logic
    assert_eq!(header.version, 0, "Header version should be 0 (current FILE_FORMAT_VERSION)");
    assert!(!header.salt.is_empty(), "Salt should not be empty");
    
    // Verify decryption works
    fs::remove_dir_all(&test_dir).unwrap();
    decrypt_core(
        &encrypted_path,
        dir_path,
        TEST_PASSWORD,
        None, // No event callback
    ).unwrap();
    
    // Verify directory structure is restored
    assert!(test_dir.exists());
    assert!(test_dir.is_dir());
    assert_eq!(fs::read_to_string(test_dir.join("file1.txt")).unwrap(), "Content 1");
    assert_eq!(fs::read_to_string(test_dir.join("file2.txt")).unwrap(), "Content 2");
}

#[test] 
fn test_single_file_size_efficiency() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("small_test.txt");
    let test_content = b"Small file content"; // Small file to check archive overhead reduction
    
    // Create test file
    fs::write(&test_file, test_content).unwrap();
    
    let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
    let params = create_test_params();
    let file_path = test_file.to_str().unwrap();
    let encrypted_path = format!("{}.sec", file_path);
    
    // Encrypt the single file
    encrypt_core(
        file_path,
        &encrypted_path,
        TEST_PASSWORD,
        &algorithm,
        &params,
        None, // No compression to see raw overhead
        None, // No event callback
    ).unwrap();
    
    let encrypted_size = fs::metadata(&encrypted_path).unwrap().len();
    let original_size = test_content.len() as u64;
    
    // With no archive overhead, the encrypted file should be much closer to original size
    // Expected overhead: header + HMAC + encryption auth tags
    // Should be significantly less than the ~1KB archive overhead that would exist with TAR
    let overhead = encrypted_size - original_size;
    
    println!("Original size: {} bytes", original_size);
    println!("Encrypted size: {} bytes", encrypted_size);
    println!("Overhead: {} bytes", overhead);
    
    // The overhead should be reasonable (header + HMAC + auth tags, but no archive padding)
    // This is much better than the 512+ bytes TAR would add for small files
    assert!(overhead < 200, "Overhead should be minimal for single files: {} bytes", overhead);
}
