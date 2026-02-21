// Copyright © 2025 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! VMDK (VMware Virtual Machine Disk) format support
//!
//! This module provides read-only support for flat VMDK files.
//! Flat VMDK consists of:
//! - A descriptor file (.vmdk) containing metadata
//! - One or more flat extent files containing raw disk data
//!
//! Both single-extent and multi-extent flat VMDKs are supported.
//! Sparse VMDK formats are not supported.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use crate::BlockBackend;

const VMDK_MAGIC: u32 = 0x564d444b; // "KDMV" in little-endian

/// Check if a buffer contains a VMDK descriptor or sparse header
pub fn is_vmdk(block: &[u8]) -> bool {
    if block.len() < 4 {
        return false;
    }

    // Check for sparse VMDK magic number
    let magic = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
    if magic == VMDK_MAGIC {
        return true;
    }

    // Check for descriptor file signature (starts with "# Disk DescriptorFile")
    if block.len() >= 21 {
        let prefix = &block[0..21];
        if let Ok(s) = std::str::from_utf8(prefix) {
            if s == "# Disk DescriptorFile" {
                return true;
            }
        }
    }

    false
}

/// Information about a single extent in a VMDK
#[derive(Debug)]
struct ExtentInfo {
    /// Path to the extent file (relative to descriptor)
    path: PathBuf,
    /// Size of this extent in sectors
    size_sectors: u64,
    /// Starting offset in the virtual disk (in bytes)
    start_offset: u64,
}

/// Parse a flat VMDK descriptor to extract all extent information
fn parse_flat_descriptor(mut file: File) -> std::io::Result<Vec<ExtentInfo>> {
    file.seek(SeekFrom::Start(0))?;
    let reader = BufReader::new(file);

    let mut extents = Vec::new();
    let mut current_offset = 0u64;

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Look for extent description line
        // Format: RW <size> FLAT "filename.vmdk" 0
        // or: RW <size> FLAT "filename-flat.vmdk" 0
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == "RW" && parts[2] == "FLAT" {
            // Parse size (in sectors, 512 bytes each)
            let size_sectors = parts[1].parse::<u64>().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid extent size: {}", parts[1]),
                )
            })?;

            // Parse filename (remove quotes)
            let filename = parts[3].trim_matches('"').trim_matches('\'');
            let path = PathBuf::from(filename);

            extents.push(ExtentInfo {
                path,
                size_sectors,
                start_offset: current_offset,
            });

            current_offset += size_sectors * 512;
        }
    }

    if extents.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Failed to parse VMDK descriptor: no FLAT extent definitions found",
        ));
    }

    Ok(extents)
}

/// A single extent file with its metadata
#[derive(Debug)]
pub struct Extent {
    pub file: File,
    pub start_offset: u64,
    pub size: u64,
}

impl Extent {
    fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.start_offset && offset < self.start_offset + self.size
    }

    fn offset_in_extent(&self, virtual_offset: u64) -> u64 {
        virtual_offset - self.start_offset
    }
}

/// Flat VMDK disk representation
///
/// This struct represents a flat VMDK disk which consists of:
/// - A descriptor file containing metadata
/// - One or more flat extent files containing raw disk data
#[derive(Debug)]
pub struct FlatVmdk {
    extents: Vec<Extent>,
    total_size: u64,
    position: u64,
}

impl FlatVmdk {
    /// Create a new FlatVmdk from a descriptor file
    ///
    /// # Arguments
    /// * `descriptor_file` - The VMDK descriptor file
    /// * `descriptor_path` - Path to the descriptor file (needed to resolve relative extent paths)
    pub fn new(descriptor_file: File, descriptor_path: &Path) -> std::io::Result<Self> {
        // First check if this is a sparse VMDK (not supported)
        let mut header = [0u8; 4];
        let mut peek_file = descriptor_file.try_clone()?;
        peek_file.seek(SeekFrom::Start(0))?;
        peek_file.read_exact(&mut header)?;
        let magic = u32::from_le_bytes(header);

        if magic == VMDK_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Sparse VMDK files are not supported. Please convert to flat VMDK format using:\n\
                 qemu-img convert -f vmdk -O vmdk -o subformat=monolithicFlat input.vmdk output.vmdk",
            ));
        }

        // Parse the descriptor to get all extents
        let extent_infos = parse_flat_descriptor(descriptor_file)?;

        // Resolve extent paths and open files
        let descriptor_dir = descriptor_path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid descriptor path: no parent directory",
            )
        })?;

        let mut extents = Vec::new();
        let mut total_size = 0u64;

        for info in extent_infos {
            let extent_path = descriptor_dir.join(&info.path);
            let size = info.size_sectors * 512;

            // Open the extent file (read-only)
            let extent_file = File::open(&extent_path).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to open VMDK extent file '{}': {}",
                        extent_path.display(),
                        e
                    ),
                )
            })?;

            // Verify the extent file size matches the descriptor
            let actual_size = extent_file.metadata()?.len();
            if actual_size != size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "VMDK extent file '{}' size mismatch: descriptor says {} bytes, file is {} bytes",
                        extent_path.display(),
                        size,
                        actual_size
                    ),
                ));
            }

            extents.push(Extent {
                file: extent_file,
                start_offset: info.start_offset,
                size,
            });

            total_size += size;
        }

        Ok(Self {
            extents,
            total_size,
            position: 0,
        })
    }

    /// Find the extent that contains the given offset
    fn find_extent(&self, offset: u64) -> Option<usize> {
        self.extents
            .iter()
            .position(|extent| extent.contains_offset(offset))
    }

    /// Get a reference to the extents (for vmdk_sync to access file descriptors)
    pub fn extents(&self) -> &[Extent] {
        &self.extents
    }
}

impl AsRawFd for FlatVmdk {
    fn as_raw_fd(&self) -> RawFd {
        // Return the first extent's fd
        // Note: This is primarily for compatibility, but multi-extent VMDKs
        // should use the custom AsyncIo implementation instead
        self.extents[0].file.as_raw_fd()
    }
}

impl Read for FlatVmdk {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.position >= self.total_size {
            return Ok(0); // EOF
        }

        let mut total_read = 0;
        let mut remaining = buf.len();

        while remaining > 0 && self.position < self.total_size {
            // Find the extent containing current position
            let extent_idx = self.find_extent(self.position).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("No extent found for offset {}", self.position),
                )
            })?;

            let extent = &mut self.extents[extent_idx];
            let offset_in_extent = extent.offset_in_extent(self.position);
            let bytes_left_in_extent = extent.size - offset_in_extent;
            let bytes_to_read = remaining.min(bytes_left_in_extent as usize);

            // Seek to the correct position in the extent file
            extent.file.seek(SeekFrom::Start(offset_in_extent))?;

            // Read from the extent
            let bytes_read = extent.file.read(&mut buf[total_read..total_read + bytes_to_read])?;
            if bytes_read == 0 {
                break; // Unexpected EOF in extent
            }

            total_read += bytes_read;
            self.position += bytes_read as u64;
            remaining -= bytes_read;

            if bytes_read < bytes_to_read {
                break; // Short read
            }
        }

        Ok(total_read)
    }
}

impl Write for FlatVmdk {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "VMDK is read-only",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Read-only, nothing to flush
        Ok(())
    }
}

impl Seek for FlatVmdk {
    fn seek(&mut self, newpos: SeekFrom) -> std::io::Result<u64> {
        let new_position = match newpos {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::Current(offset) => self.position as i64 + offset,
            SeekFrom::End(offset) => self.total_size as i64 + offset,
        };

        if new_position < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid seek to negative position",
            ));
        }

        self.position = new_position as u64;
        Ok(self.position)
    }
}

impl BlockBackend for FlatVmdk {
    fn logical_size(&self) -> Result<u64, crate::Error> {
        Ok(self.total_size)
    }

    fn physical_size(&self) -> Result<u64, crate::Error> {
        // Sum up all extent file sizes
        let mut total = 0u64;
        for extent in &self.extents {
            total += extent
                .file
                .metadata()
                .map_err(crate::Error::GetFileMetadata)?
                .len();
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmdk_detection_descriptor() {
        let descriptor = b"# Disk DescriptorFile\nversion=1\n";
        assert!(is_vmdk(descriptor));
    }

    #[test]
    fn test_vmdk_detection_sparse_magic() {
        let mut sparse_header = vec![0u8; 512];
        sparse_header[0..4].copy_from_slice(&VMDK_MAGIC.to_le_bytes());
        assert!(is_vmdk(&sparse_header));
    }

    #[test]
    fn test_vmdk_detection_negative() {
        let raw_data = vec![0u8; 512];
        assert!(!is_vmdk(&raw_data));

        let qcow_magic = 0x5146_49fbu32.to_be_bytes();
        assert!(!is_vmdk(&qcow_magic));
    }

    #[test]
    fn test_vmdk_detection_short_block() {
        let short = b"# Disk";
        assert!(!is_vmdk(short));
    }

    #[cfg(test)]
    mod integration_tests {
        use super::*;

        fn qemu_img_available() -> bool {
            std::process::Command::new("qemu-img")
                .arg("--version")
                .output()
                .is_ok()
        }

        #[test]
        fn test_vmdk_format_detection_sparse() {
            if !qemu_img_available() {
                eprintln!("Skipping test: qemu-img not available");
                return;
            }

            let temp_dir = std::env::temp_dir();
            let vmdk_path = temp_dir.join("test_detect_sparse.vmdk");

            // Create a sparse VMDK
            let output = std::process::Command::new("qemu-img")
                .args([
                    "create",
                    "-f",
                    "vmdk",
                    vmdk_path.to_str().unwrap(),
                    "1M",
                ])
                .output()
                .expect("Failed to create test VMDK");

            assert!(output.status.success());

            let mut file = std::fs::File::open(&vmdk_path).expect("Failed to open VMDK");

            // Detect as VMDK via magic header
            let image_type =
                crate::detect_image_type(&mut file).expect("Failed to detect image type");
            assert_eq!(
                image_type,
                crate::ImageType::Vmdk,
                "Should detect sparse VMDK"
            );

            // Cleanup
            let _ = std::fs::remove_file(&vmdk_path);
        }

        #[test]
        fn test_vmdk_format_detection_flat() {
            if !qemu_img_available() {
                eprintln!("Skipping test: qemu-img not available");
                return;
            }

            let temp_dir = std::env::temp_dir();
            let vmdk_path = temp_dir.join("test_detect_flat.vmdk");
            let flat_path = temp_dir.join("test_detect_flat-flat.vmdk");

            // Create a flat VMDK
            let output = std::process::Command::new("qemu-img")
                .args([
                    "create",
                    "-f",
                    "vmdk",
                    "-o",
                    "subformat=monolithicFlat",
                    vmdk_path.to_str().unwrap(),
                    "10M",
                ])
                .output()
                .expect("Failed to create test VMDK");

            assert!(output.status.success());

            let mut file = std::fs::File::open(&vmdk_path).expect("Failed to open VMDK");

            // Verify that flat VMDK descriptor is correctly detected
            let image_type =
                crate::detect_image_type(&mut file).expect("Should successfully detect flat VMDK");
            assert_eq!(
                image_type,
                crate::ImageType::Vmdk,
                "Should detect flat VMDK"
            );

            // Cleanup
            let _ = std::fs::remove_file(&vmdk_path);
            let _ = std::fs::remove_file(&flat_path);
        }

        #[test]
        fn test_open_flat_vmdk() {
            if !qemu_img_available() {
                eprintln!("Skipping test: qemu-img not available");
                return;
            }

            let temp_dir = std::env::temp_dir();
            let vmdk_path = temp_dir.join("test_open.vmdk");
            let flat_path = temp_dir.join("test_open-flat.vmdk");

            // Create a flat VMDK
            let output = std::process::Command::new("qemu-img")
                .args([
                    "create",
                    "-f",
                    "vmdk",
                    "-o",
                    "subformat=monolithicFlat",
                    vmdk_path.to_str().unwrap(),
                    "10M",
                ])
                .output()
                .expect("Failed to create test VMDK");

            assert!(output.status.success());

            // Open and verify
            let file = std::fs::File::open(&vmdk_path).expect("Failed to open VMDK");
            let vmdk = FlatVmdk::new(file, &vmdk_path).expect("Failed to create FlatVmdk");

            let size = vmdk.logical_size().expect("Failed to get size");
            assert_eq!(size, 10 * 1024 * 1024, "Size should be 10MB");
            assert_eq!(vmdk.extents.len(), 1, "Should have 1 extent");

            // Cleanup
            let _ = std::fs::remove_file(&vmdk_path);
            let _ = std::fs::remove_file(&flat_path);
        }

        #[test]
        fn test_sparse_vmdk_rejected_with_clear_error() {
            if !qemu_img_available() {
                eprintln!("Skipping test: qemu-img not available");
                return;
            }

            let temp_dir = std::env::temp_dir();
            let vmdk_path = temp_dir.join("test_sparse_reject.vmdk");

            // Create a sparse VMDK
            let output = std::process::Command::new("qemu-img")
                .args([
                    "create",
                    "-f",
                    "vmdk",
                    vmdk_path.to_str().unwrap(),
                    "1M",
                ])
                .output()
                .expect("Failed to create test VMDK");

            assert!(output.status.success());

            // Try to open - should fail with clear error
            let file = std::fs::File::open(&vmdk_path).expect("Failed to open VMDK");
            let result = FlatVmdk::new(file, &vmdk_path);

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
            assert!(
                err.to_string().contains("Sparse VMDK files are not supported"),
                "Error message should mention sparse VMDK: {}",
                err
            );
            assert!(
                err.to_string().contains("qemu-img convert"),
                "Error message should mention qemu-img convert: {}",
                err
            );

            // Cleanup
            let _ = std::fs::remove_file(&vmdk_path);
        }

        #[test]
        fn test_vmdk_physical_vs_logical_size() {
            if !qemu_img_available() {
                eprintln!("Skipping test: qemu-img not available");
                return;
            }

            let temp_dir = std::env::temp_dir();
            let vmdk_path = temp_dir.join("test_size.vmdk");
            let flat_path = temp_dir.join("test_size-flat.vmdk");

            // Create a 5MB flat VMDK
            let output = std::process::Command::new("qemu-img")
                .args([
                    "create",
                    "-f",
                    "vmdk",
                    "-o",
                    "subformat=monolithicFlat",
                    vmdk_path.to_str().unwrap(),
                    "5M",
                ])
                .output()
                .expect("Failed to create test VMDK");

            assert!(output.status.success());

            let file = std::fs::File::open(&vmdk_path).expect("Failed to open VMDK");
            let vmdk = FlatVmdk::new(file, &vmdk_path).expect("Failed to create FlatVmdk");

            let logical = vmdk.logical_size().expect("Failed to get logical size");
            let physical = vmdk.physical_size().expect("Failed to get physical size");

            assert_eq!(logical, 5 * 1024 * 1024, "Logical size should be 5MB");
            assert_eq!(
                physical, 5 * 1024 * 1024,
                "Physical size should be 5MB for flat VMDK"
            );

            // Cleanup
            let _ = std::fs::remove_file(&vmdk_path);
            let _ = std::fs::remove_file(&flat_path);
        }

        #[test]
        fn test_vmdk_write_fails() {
            if !qemu_img_available() {
                eprintln!("Skipping test: qemu-img not available");
                return;
            }

            let temp_dir = std::env::temp_dir();
            let vmdk_path = temp_dir.join("test_readonly.vmdk");
            let flat_path = temp_dir.join("test_readonly-flat.vmdk");

            // Create a flat VMDK
            let output = std::process::Command::new("qemu-img")
                .args([
                    "create",
                    "-f",
                    "vmdk",
                    "-o",
                    "subformat=monolithicFlat",
                    vmdk_path.to_str().unwrap(),
                    "1M",
                ])
                .output()
                .expect("Failed to create test VMDK");

            assert!(output.status.success());

            let file = std::fs::File::open(&vmdk_path).expect("Failed to open VMDK");
            let mut vmdk = FlatVmdk::new(file, &vmdk_path).expect("Failed to create FlatVmdk");

            // Try to write - should fail
            let data = vec![0u8; 512];
            let result = vmdk.write(&data);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

            // Cleanup
            let _ = std::fs::remove_file(&vmdk_path);
            let _ = std::fs::remove_file(&flat_path);
        }

        #[test]
        fn test_vmdk_read_write() {
            if !qemu_img_available() {
                eprintln!("Skipping test: qemu-img not available");
                return;
            }

            let temp_dir = std::env::temp_dir();
            let vmdk_path = temp_dir.join("test_rw.vmdk");
            let flat_path = temp_dir.join("test_rw-flat.vmdk");

            // Create and write test data to flat file
            let output = std::process::Command::new("qemu-img")
                .args([
                    "create",
                    "-f",
                    "vmdk",
                    "-o",
                    "subformat=monolithicFlat",
                    vmdk_path.to_str().unwrap(),
                    "1M",
                ])
                .output()
                .expect("Failed to create test VMDK");

            assert!(output.status.success());

            // Write test pattern to the flat file
            let test_data = vec![0x42u8; 4096];
            {
                use std::io::Write;
                let mut flat_file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&flat_path)
                    .expect("Failed to open flat file for writing");
                flat_file
                    .write_all(&test_data)
                    .expect("Failed to write test data");
            }

            // Read through FlatVmdk
            let file = std::fs::File::open(&vmdk_path).expect("Failed to open VMDK");
            let mut vmdk = FlatVmdk::new(file, &vmdk_path).expect("Failed to create FlatVmdk");

            let mut read_buf = vec![0u8; 4096];
            vmdk.read_exact(&mut read_buf)
                .expect("Failed to read from VMDK");
            assert_eq!(read_buf, test_data, "Read data should match written data");

            // Cleanup
            let _ = std::fs::remove_file(&vmdk_path);
            let _ = std::fs::remove_file(&flat_path);
        }

        #[test]
        fn test_multi_extent_vmdk() {
            let temp_dir = std::env::temp_dir();
            let vmdk_path = temp_dir.join("test_multi.vmdk");
            let extent1_path = temp_dir.join("test_multi-extent1.vmdk");
            let extent2_path = temp_dir.join("test_multi-extent2.vmdk");
            let extent3_path = temp_dir.join("test_multi-extent3.vmdk");

            // Create extent files with different patterns
            // Extent 1: 8 sectors (4KB) - pattern 0x11
            let extent1_data = vec![0x11u8; 4096];
            std::fs::write(&extent1_path, &extent1_data).expect("Failed to write extent 1");

            // Extent 2: 24 sectors (12KB) - pattern 0x22
            let extent2_data = vec![0x22u8; 12288];
            std::fs::write(&extent2_path, &extent2_data).expect("Failed to write extent 2");

            // Extent 3: 32 sectors (16KB) - pattern 0x33
            let extent3_data = vec![0x33u8; 16384];
            std::fs::write(&extent3_path, &extent3_data).expect("Failed to write extent 3");

            // Create descriptor file
            let descriptor = format!(
                r#"# Disk DescriptorFile
version=1
CID=cd09d130
parentCID=ffffffff
createType="twoGbMaxExtentFlat"

# Extent description
RW 8 FLAT "{}" 0
RW 24 FLAT "{}" 0
RW 32 FLAT "{}" 0

# The Disk Data Base
#DDB

ddb.virtualHWVersion = "4"
ddb.geometry.cylinders = "8"
ddb.geometry.heads = "16"
ddb.geometry.sectors = "63"
ddb.adapterType = "ide"
"#,
                extent1_path.file_name().unwrap().to_str().unwrap(),
                extent2_path.file_name().unwrap().to_str().unwrap(),
                extent3_path.file_name().unwrap().to_str().unwrap(),
            );

            std::fs::write(&vmdk_path, descriptor).expect("Failed to write descriptor");

            // Open the multi-extent VMDK
            let file = std::fs::File::open(&vmdk_path).expect("Failed to open VMDK");
            let mut vmdk = FlatVmdk::new(file, &vmdk_path).expect("Failed to create FlatVmdk");

            // Verify size: 8 + 24 + 32 = 64 sectors = 32KB
            let size = vmdk.logical_size().expect("Failed to get size");
            assert_eq!(size, 32768, "Size should be 32KB (64 sectors)");
            assert_eq!(vmdk.extents.len(), 3, "Should have 3 extents");

            // Test 1: Read from first extent (offset 0, 4KB)
            let mut buf1 = vec![0u8; 4096];
            vmdk.seek(SeekFrom::Start(0)).expect("Failed to seek");
            vmdk.read_exact(&mut buf1).expect("Failed to read extent 1");
            assert!(
                buf1.iter().all(|&b| b == 0x11),
                "Extent 1 should contain 0x11"
            );

            // Test 2: Read from second extent (offset 4KB, 12KB)
            let mut buf2 = vec![0u8; 12288];
            vmdk.seek(SeekFrom::Start(4096)).expect("Failed to seek");
            vmdk.read_exact(&mut buf2).expect("Failed to read extent 2");
            assert!(
                buf2.iter().all(|&b| b == 0x22),
                "Extent 2 should contain 0x22"
            );

            // Test 3: Read from third extent (offset 16KB, 16KB)
            let mut buf3 = vec![0u8; 16384];
            vmdk.seek(SeekFrom::Start(16384)).expect("Failed to seek");
            vmdk.read_exact(&mut buf3).expect("Failed to read extent 3");
            assert!(
                buf3.iter().all(|&b| b == 0x33),
                "Extent 3 should contain 0x33"
            );

            // Test 4: Read across extent boundary (extent 1 -> extent 2)
            // Read 8KB starting at offset 2KB (2KB from extent1 + 6KB from extent2)
            let mut buf_cross1 = vec![0u8; 8192];
            vmdk.seek(SeekFrom::Start(2048)).expect("Failed to seek");
            vmdk.read_exact(&mut buf_cross1)
                .expect("Failed to read across boundary");
            assert!(
                buf_cross1[0..2048].iter().all(|&b| b == 0x11),
                "First 2KB should be from extent 1"
            );
            assert!(
                buf_cross1[2048..8192].iter().all(|&b| b == 0x22),
                "Next 6KB should be from extent 2"
            );

            // Test 5: Read across extent boundary (extent 2 -> extent 3)
            // Read 8KB starting at offset 12KB (4KB from extent2 + 4KB from extent3)
            let mut buf_cross2 = vec![0u8; 8192];
            vmdk.seek(SeekFrom::Start(12288)).expect("Failed to seek");
            vmdk.read_exact(&mut buf_cross2)
                .expect("Failed to read across boundary");
            assert!(
                buf_cross2[0..4096].iter().all(|&b| b == 0x22),
                "First 4KB should be from extent 2"
            );
            assert!(
                buf_cross2[4096..8192].iter().all(|&b| b == 0x33),
                "Next 4KB should be from extent 3"
            );

            // Test 6: Read across all three extents
            // Read 24KB starting at offset 2KB
            let mut buf_all = vec![0u8; 24576];
            vmdk.seek(SeekFrom::Start(2048)).expect("Failed to seek");
            vmdk.read_exact(&mut buf_all)
                .expect("Failed to read across all extents");
            assert!(
                buf_all[0..2048].iter().all(|&b| b == 0x11),
                "First 2KB should be from extent 1"
            );
            assert!(
                buf_all[2048..14336].iter().all(|&b| b == 0x22),
                "Next 12KB should be from extent 2"
            );
            assert!(
                buf_all[14336..24576].iter().all(|&b| b == 0x33),
                "Last 10KB should be from extent 3"
            );

            // Test 7: Verify position tracking
            vmdk.seek(SeekFrom::Start(0)).expect("Failed to seek");
            let pos = vmdk.seek(SeekFrom::Current(0)).expect("Failed to get position");
            assert_eq!(pos, 0, "Position should be 0");

            vmdk.seek(SeekFrom::End(0)).expect("Failed to seek to end");
            let pos = vmdk.seek(SeekFrom::Current(0)).expect("Failed to get position");
            assert_eq!(pos, 32768, "Position should be at end (32KB)");

            // Cleanup
            let _ = std::fs::remove_file(&vmdk_path);
            let _ = std::fs::remove_file(&extent1_path);
            let _ = std::fs::remove_file(&extent2_path);
            let _ = std::fs::remove_file(&extent3_path);
        }
    }
}
