use std::fs::{self, File};
use std::path::Path;
use std::io::{Write, Cursor};
use anyhow::{Result, Context, bail};
use tar::{Builder, Archive};

use crate::progress::*;

/// Extract TAR archive to directory with progress tracking
pub fn extract_tar_to_directory(tar_data: &[u8], output_dir: &Path) -> Result<()> {
    println!("Extracting TAR archive...");
    
    // Count entries for progress (we need to read the archive twice for this)
    let cursor_count = Cursor::new(tar_data);
    let mut archive_count = Archive::new(cursor_count);
    let total_entries = archive_count.entries()?.count() as u64;
    
    let pb = create_standard_progress_bar(total_entries, "Extracting TAR");
    pb.set_message("Preparing...");
    
    // Now extract the files
    let cursor_extract = Cursor::new(tar_data);
    let mut archive_extract = Archive::new(cursor_extract);
    
    for (i, entry) in archive_extract.entries()?.enumerate() {
        let mut entry = entry.context("Failed to read TAR entry")?;
        
        let path = entry.path()?.to_path_buf();
        pb.set_message(format!("Extracting: {}", path.display()));
        
        entry.unpack_in(output_dir)
            .with_context(|| format!("Failed to extract: {}", path.display()))?;
        
        pb.set_position(i as u64 + 1);
    }
    
    pb.finish_with_message("TAR extraction complete!");
    Ok(())
}

/// Count files in directory recursively for progress tracking
pub fn count_files_in_directory(dir_path: &Path) -> Result<u64> {
    let mut count = 0;
    let entries = fs::read_dir(dir_path)
        .with_context(|| format!("Failed to read directory: {}", dir_path.display()))?;
    
    for entry in entries {
        let entry = entry.context("Failed to read directory entry")?;
        let path = entry.path();
        
        if path.is_dir() {
            count += 1; // Count the directory itself
            count += count_files_in_directory(&path)?; // Recursively count contents
        } else {
            count += 1; // Count the file
        }
    }
    
    Ok(count)
}

/// Recursively add directory contents to streaming TAR builder
pub fn stream_tar_directory_recursive<W: Write>(
    base_path: &Path,
    current_path: &Path,
    tar: &mut Builder<W>,
    pb: &indicatif::ProgressBar,
    processed_files: &mut u64,
) -> Result<()> {
    let entries = fs::read_dir(current_path)
        .with_context(|| format!("Failed to read directory: {}", current_path.display()))?;
    
    for entry in entries {
        let entry = entry.context("Failed to read directory entry")?;
        let path = entry.path();
        let relative_path = path.strip_prefix(base_path)
            .context("Failed to create relative path")?;
        
        if path.is_dir() {
            // Add directory to TAR
            tar.append_dir(relative_path, &path)
                .with_context(|| format!("Failed to add directory to tar: {}", relative_path.display()))?;
            
            // Update progress
            *processed_files += 1;
            pb.set_position(*processed_files);
            pb.set_message(format!("Adding directory: {}", relative_path.display()));
            
            // Recursively add directory contents
            stream_tar_directory_recursive(base_path, &path, tar, pb, processed_files)?;
        } else {
            // Add file to TAR with streaming
            let mut file = File::open(&path)
                .with_context(|| format!("Failed to open file: {}", path.display()))?;
            
            tar.append_file(relative_path, &mut file)
                .with_context(|| format!("Failed to add file to tar: {}", relative_path.display()))?;
            
            // Update progress
            *processed_files += 1;
            pb.set_position(*processed_files);
            pb.set_message(format!("Adding file: {}", relative_path.display()));
        }
    }
    
    Ok(())
}

/// Check if TAR archive contains a single file (for extraction path determination)
pub fn tar_contains_single_file(tar_data: &[u8]) -> Result<bool> {
    let tar_cursor = Cursor::new(tar_data);
    let mut tar_archive = Archive::new(tar_cursor);
    let entries: Result<Vec<_>, _> = tar_archive.entries()?.collect();
    let entries = entries.context("Failed to read TAR entries")?;
    
    Ok(entries.len() == 1)
}

/// Extract single file from TAR archive to specified path
pub fn extract_single_file_from_tar(tar_data: &[u8], output_path: &str) -> Result<()> {
    let tar_cursor = Cursor::new(tar_data);
    let mut tar_archive = Archive::new(tar_cursor);
    let mut entries = tar_archive.entries()?;
    
    if let Some(entry) = entries.next() {
        let mut entry = entry.context("Failed to read TAR entry")?;
        let mut output_file = File::create(output_path)
            .with_context(|| format!("Failed to create output file: {}", output_path))?;
        
        std::io::copy(&mut entry, &mut output_file)
            .context("Failed to extract file from TAR")?;
        
        println!("File extracted successfully: {}", output_path);
        Ok(())
    } else {
        bail!("TAR archive is empty")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use tar::Builder;
    
    #[test]
    fn test_count_files_in_directory_empty() {
        let temp_dir = TempDir::new().unwrap();
        
        let count = count_files_in_directory(temp_dir.path()).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_count_files_in_directory_with_files() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create some test files
        fs::write(temp_dir.path().join("file1.txt"), b"content1").unwrap();
        fs::write(temp_dir.path().join("file2.txt"), b"content2").unwrap();
        
        let count = count_files_in_directory(temp_dir.path()).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_count_files_in_directory_with_subdirs() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create files and subdirectories
        fs::write(temp_dir.path().join("file1.txt"), b"content1").unwrap();
        
        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("file2.txt"), b"content2").unwrap();
        fs::write(subdir.join("file3.txt"), b"content3").unwrap();
        
        let count = count_files_in_directory(temp_dir.path()).unwrap();
        assert_eq!(count, 4); // Should count all files and directories recursively (1 file + 1 dir + 2 files)
    }

    #[test]
    fn test_count_files_nonexistent_directory() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent = temp_dir.path().join("nonexistent");
        
        let result = count_files_in_directory(&nonexistent);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_tar_to_directory() {
        let temp_dir = TempDir::new().unwrap();
        let extract_dir = temp_dir.path().join("extract");
        fs::create_dir(&extract_dir).unwrap();
        
        // Create a TAR archive in memory
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            
            // Add some test files to the TAR
            let mut header = tar::Header::new_gnu();
            header.set_size(6);
            header.set_cksum();
            builder.append_data(&mut header, "file1.txt", "hello1".as_bytes()).unwrap();
            
            let mut header = tar::Header::new_gnu();
            header.set_size(6);
            header.set_cksum();
            builder.append_data(&mut header, "file2.txt", "hello2".as_bytes()).unwrap();
            
            builder.finish().unwrap();
        }
        
        // Extract the TAR
        extract_tar_to_directory(&tar_data, &extract_dir).unwrap();
        
        // Verify extracted files
        let file1_content = fs::read_to_string(extract_dir.join("file1.txt")).unwrap();
        let file2_content = fs::read_to_string(extract_dir.join("file2.txt")).unwrap();
        
        assert_eq!(file1_content, "hello1");
        assert_eq!(file2_content, "hello2");
    }

    #[test]
    fn test_extract_single_file_from_tar() {
        let temp_dir = TempDir::new().unwrap();
        let output_file = temp_dir.path().join("extracted.txt");
        
        // Create a TAR archive with a single file
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            
            let mut header = tar::Header::new_gnu();
            header.set_size(12);
            header.set_cksum();
            builder.append_data(&mut header, "single.txt", "single file!".as_bytes()).unwrap();
            
            builder.finish().unwrap();
        }
        
        // Extract the single file
        extract_single_file_from_tar(&tar_data, output_file.to_str().unwrap()).unwrap();
        
        // Verify extracted file
        let content = fs::read_to_string(&output_file).unwrap();
        assert_eq!(content, "single file!");
    }

    #[test]
    fn test_extract_single_file_from_empty_tar() {
        let temp_dir = TempDir::new().unwrap();
        let output_file = temp_dir.path().join("extracted.txt");
        
        // Create an empty TAR archive
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            builder.finish().unwrap();
        }
        
        // Try to extract from empty TAR (should fail)
        let result = extract_single_file_from_tar(&tar_data, output_file.to_str().unwrap());
        assert!(result.is_err());
        assert!(!output_file.exists());
    }

    #[test]
    fn test_stream_tar_directory_recursive() {
        let temp_dir = TempDir::new().unwrap();
        let source_dir = temp_dir.path().join("source");
        fs::create_dir(&source_dir).unwrap();
        
        // Create test directory structure
        fs::write(source_dir.join("file1.txt"), b"content1").unwrap();
        fs::write(source_dir.join("file2.txt"), b"content2").unwrap();
        
        let subdir = source_dir.join("subdir");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("file3.txt"), b"content3").unwrap();
        
        // Create TAR archive
        let mut tar_data = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_data);
            let pb = create_standard_progress_bar(4, "Testing TAR");
            let mut processed = 0;
            
            stream_tar_directory_recursive(&source_dir, &source_dir, &mut builder, &pb, &mut processed).unwrap();
            builder.finish().unwrap();
            pb.finish();
        }
        
        // Verify TAR contains all files and directories
        let cursor = Cursor::new(&tar_data);
        let mut archive = Archive::new(cursor);
        let entries: Vec<_> = archive.entries().unwrap().collect();
        
        assert_eq!(entries.len(), 4); // Should have 4 entries (2 files + 1 directory + 1 file in subdir)
        
        // Extract and verify
        let extract_dir = temp_dir.path().join("extract");
        fs::create_dir(&extract_dir).unwrap();
        extract_tar_to_directory(&tar_data, &extract_dir).unwrap();
        
        assert_eq!(fs::read_to_string(extract_dir.join("file1.txt")).unwrap(), "content1");
        assert_eq!(fs::read_to_string(extract_dir.join("file2.txt")).unwrap(), "content2");
        assert_eq!(fs::read_to_string(extract_dir.join("subdir/file3.txt")).unwrap(), "content3");
    }

    #[test]
    fn test_extract_tar_invalid_data() {
        let temp_dir = TempDir::new().unwrap();
        let extract_dir = temp_dir.path().join("extract");
        fs::create_dir(&extract_dir).unwrap();
        
        // Try to extract invalid TAR data
        let invalid_data = b"not a valid tar archive";
        let result = extract_tar_to_directory(invalid_data, &extract_dir);
        
        assert!(result.is_err());
    }
}
