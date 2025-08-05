//! Custom sec archive format for minimal overhead
//! 
//! This module provides a lightweight streaming archive format specifically designed
//! for efficient encryption and archival without the overhead of traditional formats like TAR.
//!
//! Format: [name_len: u16][name: utf8][size: u64][data]

use std::fs::{self, File};
use std::path::Path;
use std::io::{Read, Write};
use crate::error::{SecifyError, Result};
use crate::progress::EncryptProgress;

/// Custom sec archive writer for minimal overhead
/// Format: [name_len: u16][name: utf8][size: u64][data]
pub struct SecArchiveWriter<W: Write> {
    writer: W,
}

impl<W: Write> SecArchiveWriter<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
    
    pub fn add_file(&mut self, path: &str, size: u64, mut reader: impl Read) -> std::io::Result<()> {
        // Write name length and name
        let name_bytes = path.as_bytes();
        self.writer.write_all(&(name_bytes.len() as u16).to_le_bytes())?;
        self.writer.write_all(name_bytes)?;
        
        // Write file size
        self.writer.write_all(&size.to_le_bytes())?;
        
        // Copy file data
        std::io::copy(&mut reader, &mut self.writer)?;
        
        Ok(())
    }
    
    pub fn finish(self) -> W {
        self.writer
    }
}

/// Custom sec archive reader for minimal overhead
pub struct SecArchiveReader<R: Read> {
    reader: R,
}

impl<R: Read> SecArchiveReader<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }
    
    pub fn next_entry(&mut self) -> std::io::Result<Option<(String, u64)>> {
        // Try to read name length
        let mut name_len_bytes = [0u8; 2];
        match self.reader.read_exact(&mut name_len_bytes) {
            Ok(()) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        
        let name_len = u16::from_le_bytes(name_len_bytes) as usize;
        if name_len > u16::MAX as usize { 
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Name too long"));
        }
        
        // Read name
        let mut name_bytes = vec![0u8; name_len];
        self.reader.read_exact(&mut name_bytes)?;
        let name = String::from_utf8(name_bytes)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-8 in filename"))?;
        
        // Read file size
        let mut size_bytes = [0u8; 8];
        self.reader.read_exact(&mut size_bytes)?;
        let size = u64::from_le_bytes(size_bytes);
        
        Ok(Some((name, size)))
    }
    
    pub fn read_file_data(&mut self, size: u64, mut writer: impl Write) -> std::io::Result<()> {
        let mut remaining = size;
        // Use larger buffer for better performance - 256KB
        let mut buffer = vec![0u8; 256 * 1024];
        
        while remaining > 0 {
            let to_read = std::cmp::min(buffer.len() as u64, remaining) as usize;
            let bytes_read = self.reader.read(&mut buffer[..to_read])?;
            if bytes_read == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Unexpected end of archive"));
            }
            
            writer.write_all(&buffer[..bytes_read])?;
            remaining -= bytes_read as u64;
        }
        
        Ok(())
    }
}

/// Process directory with sec archive format
pub fn process_directory_sec<W: Write, P>(
    input_path: &Path,
    archive_builder: &mut SecArchiveWriter<W>,
    progress_callback: P,
) -> Result<()>
where
    P: Fn(EncryptProgress),
{
    progress_callback(EncryptProgress::CountingFiles);
    let total_files = count_files_in_directory_core(input_path)?;
    progress_callback(EncryptProgress::FileCountComplete { total_files });
    
    let mut processed_files = 0;
    stream_sec_directory_recursive(
        input_path,
        input_path,
        archive_builder,
        &mut processed_files,
        &progress_callback,
    )?;
    Ok(())
}

/// Count files in directory recursively for progress tracking
pub fn count_files_in_directory_core(dir_path: &Path) -> Result<u64> {
    let mut count = 0;
    let entries = fs::read_dir(dir_path)
        .map_err(|e| SecifyError::file_error(format!("Failed to read directory {}: {}", dir_path.display(), e)))?;
    
    for entry in entries {
        let entry = entry.map_err(|e| SecifyError::file_error(format!("Failed to read directory entry: {}", e)))?;
        let path = entry.path();
        
        if path.is_dir() {
            count += 1; // Count the directory itself
            count += count_files_in_directory_core(&path)?; // Recursively count contents
        } else {
            count += 1; // Count the file
        }
    }
    
    Ok(count)
}

/// Recursively add directory contents to sec archive builder
pub fn stream_sec_directory_recursive<W: Write>(
    base_path: &Path,
    current_path: &Path,
    archive: &mut SecArchiveWriter<W>,
    processed_files: &mut u64,
    progress_callback: &dyn Fn(EncryptProgress),
) -> Result<()>
{
    let entries = fs::read_dir(current_path)
        .map_err(|e| SecifyError::file_error(format!("Failed to read directory {}: {}", current_path.display(), e)))?;
    
    for entry in entries {
        let entry = entry.map_err(|e| SecifyError::file_error(format!("Failed to read directory entry: {}", e)))?;
        let path = entry.path();
        let relative_path = path.strip_prefix(base_path)
            .map_err(|e| SecifyError::file_error(format!("Failed to create relative path: {}", e)))?;
        
        if path.is_dir() {
            // For directories, add a special entry with "/" suffix and zero size
            // Convert to forward slashes for cross-platform compatibility
            let dir_name = format!("{}/", relative_path.display().to_string().replace('\\', "/"));
            archive.add_file(&dir_name, 0, std::io::empty())
                .map_err(|e| SecifyError::archive(format!("Failed to add directory to archive {}: {}", dir_name, e)))?;
            
            // Update progress
            *processed_files += 1;
            progress_callback(EncryptProgress::ProcessingFile { 
                current: *processed_files, 
                total: 0, // We'll update this when we know the total
                name: relative_path.display().to_string().replace('\\', "/")
            });
            
            // Recursively add directory contents
            stream_sec_directory_recursive(base_path, &path, archive, processed_files, &progress_callback)?;
        } else {
            // Add file to archive with streaming
            let file = File::open(&path)
                .map_err(|e| SecifyError::file_error(format!("Failed to open file {}: {}", path.display(), e)))?;
            
            let metadata = file.metadata()
                .map_err(|e| SecifyError::file_error(format!("Failed to get file metadata {}: {}", path.display(), e)))?;
            let file_size = metadata.len();
            
            // Convert to forward slashes for cross-platform compatibility
            let file_path = relative_path.display().to_string().replace('\\', "/");
            archive.add_file(&file_path, file_size, file)
                .map_err(|e| SecifyError::archive(format!("Failed to add file to archive {}: {}", file_path, e)))?;
            
            // Update progress
            *processed_files += 1;
            progress_callback(EncryptProgress::ProcessingFile { 
                current: *processed_files, 
                total: 0, // We'll update this when we know the total
                name: file_path 
            });
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;
    
    #[test]
    fn test_archive_roundtrip() {
        let mut buffer = Vec::new();
        let mut writer = SecArchiveWriter::new(&mut buffer);
        
        // Add test file
        let test_data = b"Hello, archive world!";
        writer.add_file("test.txt", test_data.len() as u64, &test_data[..]).unwrap();
        
        // Add directory entry
        writer.add_file("subdir/", 0, std::io::empty()).unwrap();
        
        // Read back
        let cursor = Cursor::new(buffer);
        let mut reader = SecArchiveReader::new(cursor);
        
        // First entry should be the file
        let (name, size) = reader.next_entry().unwrap().unwrap();
        assert_eq!(name, "test.txt");
        assert_eq!(size, test_data.len() as u64);
        
        let mut extracted_data = Vec::new();
        reader.read_file_data(size, &mut extracted_data).unwrap();
        assert_eq!(extracted_data, test_data);
        
        // Second entry should be the directory
        let (name, size) = reader.next_entry().unwrap().unwrap();
        assert_eq!(name, "subdir/");
        assert_eq!(size, 0);
        
        // No more entries
        assert!(reader.next_entry().unwrap().is_none());
    }
    
    #[test]
    fn test_process_directory() {
        let temp_dir = TempDir::new().unwrap();
        let test_dir = temp_dir.path().join("test_dir");
        fs::create_dir_all(&test_dir).unwrap();
        
        // Create test files
        fs::write(test_dir.join("file1.txt"), b"content1").unwrap();
        fs::create_dir_all(test_dir.join("subdir")).unwrap();
        fs::write(test_dir.join("subdir").join("file2.txt"), b"content2").unwrap();
        
        let mut buffer = Vec::new();
        let mut archive_writer = SecArchiveWriter::new(&mut buffer);
        
        process_directory_sec(&test_dir, &mut archive_writer, |_| {}).unwrap();
        
        // Verify archive contains expected entries
        let cursor = Cursor::new(buffer);
        let mut reader = SecArchiveReader::new(cursor);
        
        let mut entries = Vec::new();
        while let Some((name, size)) = reader.next_entry().unwrap() {
            entries.push((name, size));
            if size > 0 {
                let mut data = Vec::new();
                reader.read_file_data(size, &mut data).unwrap();
            }
        }
        
        assert!(entries.len() >= 3); // At least file1.txt, subdir/, and subdir/file2.txt
        assert!(entries.iter().any(|(name, _)| name == "file1.txt"));
        assert!(entries.iter().any(|(name, _)| name == "subdir/"));
        assert!(entries.iter().any(|(name, _)| name == "subdir/file2.txt"));
    }
}
