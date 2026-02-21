# VMDK Support in Cloud Hypervisor

## Overview

Cloud Hypervisor supports **read-only** flat VMDK (VMware Virtual Machine Disk) format without external dependencies. VMDK files are automatically detected when you specify a VMDK file path.

## Supported VMDK Formats

- **Flat VMDK** (monolithicFlat): Descriptor file + separate flat data file ✅
- **Multi-extent Flat VMDK** (twoGbMaxExtentFlat): Descriptor file + multiple flat extent files ✅
- **Sparse VMDK**: Not supported (rejected with helpful error message) ❌

## Features

### Automatic Detection
VMDK files are automatically detected by `detect_image_type()`:
- Sparse VMDK: Detected via magic number `0x564d444b` ("KDMV") - then rejected
- Flat VMDK: Detected via descriptor content (`# Disk DescriptorFile`)
- Special handling for small flat VMDK descriptors (<512 bytes)

### Read-Only Enforcement
VMDK disks are **always read-only** in cloud-hypervisor:
- If you specify `readonly=off` for a VMDK disk, it will be automatically forced to `readonly=on`
- A warning message is logged: `"VMDK images are read-only. Forcing readonly=true for disk '<id>'"`
- The `FlatVmdk` implementation rejects all write operations

### Small File Handling
Flat VMDK descriptor files are typically ~350 bytes, which is smaller than the 512-byte aligned block size required for O_DIRECT I/O. The detection code handles this by:
1. Attempting to read an aligned block size first
2. On `UnexpectedEof`, falling back to reading the actual file size
3. Padding the buffer to 512 bytes with zeros for detection

### Async I/O Support
Flat VMDK supports **synchronous I/O** with custom multi-extent handling:
- ✅ Synchronous I/O via custom `FlatVmdkSync` implementation
- ✅ Multi-extent routing (reads automatically go to correct extent files)
- ✅ Position-independent I/O using `pread`
- ✅ Transparent handling of extent boundaries

**Note**: Unlike single-file formats, multi-extent VMDKs cannot simply delegate to `RawFileSync` because reads may span multiple files. The implementation uses `pread` on individual extent file descriptors for correct multi-extent behavior.

## Multi-Extent VMDK Example

The implementation supports VMDKs with multiple extent files, which is useful for:
- Splitting large disks into smaller files (e.g., 2GB chunks for FAT32 compatibility)
- Container layering (different extents for different layers)

Example multi-extent descriptor:
```
# Disk DescriptorFile
version=1
CID=cd09d130
parentCID=ffffffff
createType="twoGbMaxExtentFlat"

# Extent description
RW 8 FLAT "/run/vc/vm/314b7c.../fsmeta.erofs" 0
RW 24 FLAT "/var/lib/containerd/.../snapshots/8/layer.erofs" 0
RW 1464 FLAT "/var/lib/containerd/.../snapshots/1/layer.erofs" 0
```

This creates a virtual disk with 3 extents:
- Extent 0: 8 sectors (4KB) at offset 0
- Extent 1: 24 sectors (12KB) at offset 4KB
- Extent 2: 1464 sectors (732KB) at offset 16KB
- Total: 1496 sectors (748KB)

Reads are automatically routed to the correct extent file(s). Reads that span multiple extents are handled transparently.

## Usage

### Command Line

```bash
# Automatically detected and opened as read-only
cloud-hypervisor \
  --disk path=/path/to/disk.vmdk \
  ...

# Even if you specify readonly=off, it will be forced to on
cloud-hypervisor \
  --disk path=/path/to/disk.vmdk,readonly=off \
  ...

# io_uring is supported for better performance
cloud-hypervisor \
  --disk path=/path/to/disk.vmdk \
  ...
```

### API Configuration

```json
{
  "disks": [
    {
      "path": "/path/to/disk.vmdk",
      "readonly": false  // Will be forced to true with a warning
    }
  ]
}
```

## Implementation Details

### Code Structure

**block/src/vmdk.rs** (~550 lines)
- `FlatVmdk`: Core flat VMDK implementation
- Parses descriptor file to find extent file path and size
- Opens extent file and validates size
- Implements `Read`, `Seek`, `AsRawFd`, `BlockBackend` traits
- Rejects `Write` operations with `PermissionDenied` error
- Comprehensive unit and integration tests

**block/src/vmdk_sync.rs** (~225 lines)
- `FlatVmdkDiskSync`: DiskFile wrapper for FlatVmdk
- `FlatVmdkSync`: AsyncIo implementation with multi-extent support
- `ExtentMeta`: Metadata for each extent (fd, offset, size)
- Custom `read_vectored` that routes I/O to correct extent(s)
- Handles reads spanning multiple extents transparently
- Uses `pread` for position-independent reads

**block/src/lib.rs**
- `ImageType::Vmdk`: Added to image type enum
- `detect_image_type()`: Enhanced to detect VMDK and handle small files
- Special handling for flat VMDK descriptors

**vmm/src/device_manager.rs**
- VMDK detection and readonly enforcement
- `DeviceManagerError::CreateVmdkDisk`: Error variant for VMDK creation
- Integration with virtio-block device creation
- Passes descriptor path to `FlatVmdkDiskSync::new()`

### How Flat VMDK Works

1. **Descriptor Parsing**: Reads the `.vmdk` descriptor file to extract all extents:
   - Extent file paths (e.g., `disk-flat.vmdk`, `disk-001.vmdk`, etc.)
   - Each extent's size in sectors (converted to bytes)
   - Calculates virtual disk layout (extent offsets)

2. **Extent File Access**: Opens all flat extent files containing raw disk data

3. **I/O Operations**: Reads are routed to the correct extent(s) based on offset
   - For single-extent VMDKs: Direct access to the extent file
   - For multi-extent VMDKs: Automatic routing to correct extent
   - Reads spanning multiple extents are handled transparently
   - Uses `pread` for position-independent I/O

4. **Read-Only Enforcement**: `Write` trait returns `PermissionDenied`

### No External Dependencies

Unlike the previous implementation, this version:
- ✅ No external crates (removed `imago` dependency)
- ✅ Native implementation following cloud-hypervisor patterns
- ✅ Full async I/O support (io_uring, aio)
- ✅ Simpler and more maintainable
- ✅ Better error messages

## Testing

### Unit Tests
- `test_vmdk_detection_descriptor`: Tests descriptor parsing
- `test_vmdk_detection_sparse_magic`: Tests sparse VMDK magic number
- `test_vmdk_detection_negative`: Tests non-VMDK rejection
- `test_vmdk_detection_short_block`: Tests small buffer handling

### Integration Tests (require qemu-img)
- `test_vmdk_format_detection_sparse`: Tests sparse VMDK detection (then rejection)
- `test_vmdk_format_detection_flat`: Tests flat VMDK detection with small descriptors
- `test_open_flat_vmdk`: Tests opening and size validation
- `test_vmdk_read_write`: Tests read operations (write fails as expected)
- `test_vmdk_write_fails`: Tests write rejection
- `test_vmdk_physical_vs_logical_size`: Tests size reporting
- `test_sparse_vmdk_rejected_with_clear_error`: Tests sparse VMDK rejection with clear message

Run all tests:
```bash
cargo test --package block --lib vmdk
```

## Performance

Flat VMDK performance is **identical to raw files** because:
- Descriptor is only parsed once during initialization
- All I/O operations go directly to the raw extent file
- Supports io_uring for high-performance async I/O
- No format translation or overhead

## Limitations

1. **Read-Only**: VMDK support is read-only by design
2. **Flat VMDK Only**: Sparse VMDK files are not supported
3. **No Snapshots**: VMDK snapshots and linked clones are not supported

## Converting VMDK Files

If you have a sparse or unsupported VMDK format, convert it to flat format:

```bash
# Convert sparse VMDK to flat VMDK
qemu-img convert -f vmdk -O vmdk -o subformat=monolithicFlat \
  input.vmdk output.vmdk

# Or convert to raw format for simplicity
qemu-img convert -f vmdk -O raw input.vmdk output.raw
```

## Error Messages

**Sparse VMDK Error**:
```
Sparse VMDK files are not supported. Please convert to flat VMDK format using:
qemu-img convert -f vmdk -O vmdk -o subformat=monolithicFlat input.vmdk output.vmdk
```

**Readonly Warning**:
```
VMDK images are read-only. Forcing readonly=true for disk 'disk0'
```

**Missing Extent File**:
```
Failed to open VMDK extent file '/path/to/disk-flat.vmdk': No such file or directory
```

**Size Mismatch**:
```
VMDK extent file size mismatch: descriptor says 10485760 bytes, file is 5242880 bytes
```

## Comparison with Other Formats

| Format | Read | Write | io_uring | aio | Async Overhead | Dependencies |
|--------|------|-------|----------|-----|----------------|--------------|
| Raw    | ✅   | ✅    | ✅       | ✅  | None           | None         |
| VMDK (Flat) | ✅ | ❌ | ✅       | ✅  | Descriptor parse only | None |
| QCOW2  | ✅   | ✅    | ❌       | ❌  | Format translation | None         |
| VHD    | ✅   | ✅    | ✅       | ❌  | Footer handling | None         |
| VHDX   | ✅   | ✅    | ❌       | ❌  | Format translation | None         |

## Future Enhancements

Potential future improvements:
- Write support (would require implementing VMDK change tracking)
- Multi-extent VMDK support
- Sparse VMDK support with on-demand decompression
- VMDK snapshot support

## References

- **VMDK specification**: VMware Virtual Disk Format 1.1 specification
- **Cloud Hypervisor disk docs**: See main documentation for disk configuration options
- **Flat VMDK format**: Descriptor file + raw extent file (simplest VMDK format)
