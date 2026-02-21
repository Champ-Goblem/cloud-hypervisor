// Copyright © 2025 Cloud Hypervisor Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

use vmm_sys_util::eventfd::EventFd;

use crate::BlockBackend;
use crate::async_io::{
    AsyncIo, AsyncIoError, AsyncIoResult, BorrowedDiskFd, DiskFile, DiskFileError, DiskFileResult,
};
use crate::vmdk::FlatVmdk;

pub struct FlatVmdkDiskSync(FlatVmdk);

impl FlatVmdkDiskSync {
    pub fn new(file: File, path: &Path) -> std::io::Result<Self> {
        Ok(Self(FlatVmdk::new(file, path)?))
    }
}

impl DiskFile for FlatVmdkDiskSync {
    fn logical_size(&mut self) -> DiskFileResult<u64> {
        Ok(self.0.logical_size().unwrap())
    }

    fn physical_size(&mut self) -> DiskFileResult<u64> {
        self.0.physical_size().map_err(|e| {
            let io_inner = match e {
                crate::Error::GetFileMetadata(e) => e,
                _ => unreachable!(),
            };
            DiskFileError::Size(io_inner)
        })
    }

    fn new_async_io(&self, _ring_depth: u32) -> DiskFileResult<Box<dyn AsyncIo>> {
        Ok(Box::new(
            FlatVmdkSync::new(&self.0).map_err(DiskFileError::NewAsyncIo)?,
        ) as Box<dyn AsyncIo>)
    }

    fn fd(&mut self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.0.as_raw_fd())
    }
}

/// Extent metadata for async I/O
#[derive(Debug, Clone)]
struct ExtentMeta {
    fd: RawFd,
    start_offset: u64,
    size: u64,
}

impl ExtentMeta {
    fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.start_offset && offset < self.start_offset + self.size
    }

    fn offset_in_extent(&self, virtual_offset: u64) -> u64 {
        virtual_offset - self.start_offset
    }
}

pub struct FlatVmdkSync {
    extents: Vec<ExtentMeta>,
    size: u64,
    eventfd: EventFd,
    completion_list: VecDeque<(u64, i32)>,
}

impl FlatVmdkSync {
    pub fn new(vmdk: &FlatVmdk) -> std::io::Result<Self> {
        let extents: Vec<ExtentMeta> = vmdk
            .extents()
            .iter()
            .map(|e| ExtentMeta {
                fd: e.file.as_raw_fd(),
                start_offset: e.start_offset,
                size: e.size,
            })
            .collect();

        let size = vmdk.logical_size().unwrap();

        Ok(FlatVmdkSync {
            extents,
            size,
            eventfd: EventFd::new(libc::EFD_NONBLOCK)
                .expect("Failed creating EventFd for FlatVmdkSync"),
            completion_list: VecDeque::new(),
        })
    }

    fn find_extent(&self, offset: u64) -> Option<&ExtentMeta> {
        self.extents.iter().find(|e| e.contains_offset(offset))
    }
}

impl AsyncIo for FlatVmdkSync {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn read_vectored(
        &mut self,
        offset: libc::off_t,
        iovecs: &[libc::iovec],
        user_data: u64,
    ) -> AsyncIoResult<()> {
        let offset = offset as u64;

        if offset >= self.size {
            return Err(AsyncIoError::ReadVectored(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid offset {offset}, can't be larger than file size {}",
                    self.size
                ),
            )));
        }

        // For multi-extent VMDKs, we need to handle reads that may span multiple extents
        let mut total_read = 0i32;
        let mut current_offset = offset;

        for iovec in iovecs {
            let mut buf_ptr = iovec.iov_base as *mut u8;
            let mut remaining = iovec.iov_len;

            while remaining > 0 && current_offset < self.size {
                // Find the extent containing current offset
                let extent = self.find_extent(current_offset).ok_or_else(|| {
                    AsyncIoError::ReadVectored(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("No extent found for offset {current_offset}"),
                    ))
                })?;

                let offset_in_extent = extent.offset_in_extent(current_offset);
                let bytes_left_in_extent = extent.size - offset_in_extent;
                let bytes_to_read = remaining.min(bytes_left_in_extent as usize);

                // Read from the extent file using pread
                // SAFETY: FFI call with valid arguments
                let result = unsafe {
                    libc::pread(
                        extent.fd as libc::c_int,
                        buf_ptr as *mut libc::c_void,
                        bytes_to_read,
                        offset_in_extent as libc::off_t,
                    )
                };

                if result < 0 {
                    return Err(AsyncIoError::ReadVectored(std::io::Error::last_os_error()));
                }

                if result == 0 {
                    // EOF in extent
                    break;
                }

                let bytes_read = result as usize;
                total_read += bytes_read as i32;
                current_offset += bytes_read as u64;
                remaining -= bytes_read;
                // SAFETY: Advancing pointer within valid buffer
                unsafe {
                    buf_ptr = buf_ptr.add(bytes_read);
                }

                if bytes_read < bytes_to_read {
                    // Short read
                    break;
                }
            }

            if remaining > 0 && current_offset >= self.size {
                // Hit end of disk
                break;
            }
        }

        self.completion_list.push_back((user_data, total_read));
        self.eventfd.write(1).unwrap();

        Ok(())
    }

    fn write_vectored(
        &mut self,
        _offset: libc::off_t,
        _iovecs: &[libc::iovec],
        _user_data: u64,
    ) -> AsyncIoResult<()> {
        Err(AsyncIoError::WriteVectored(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "VMDK is read-only",
        )))
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        // Read-only, nothing to flush but signal completion if requested
        if let Some(user_data) = user_data {
            self.completion_list.push_back((user_data, 0));
            self.eventfd.write(1).unwrap();
        }
        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<(u64, i32)> {
        self.completion_list.pop_front()
    }

    fn batch_requests_enabled(&self) -> bool {
        false
    }
}
