use anyhow::anyhow;
use fuse_backend_rs::abi::virtio_fs::{RemovemappingOne, SetupmappingFlags};
use fuse_backend_rs::passthrough::{Config, PassthroughFs};
use std::os::unix::prelude::{AsRawFd, RawFd};
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier};
use vhost::vhost_user::message::VhostUserFSSlaveMsgFlags;
use vhost::vhost_user::VhostUserProtocolFeatures;

use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::{
    EpollHelper, EpollHelperError, EpollHelperHandler, GuestMemoryMmap, MmapRegion,
    UserspaceMapping, VirtioCommon, VirtioDevice, VirtioInterrupt, VirtioInterruptType,
    VirtioSharedMemoryList, EPOLL_HELPER_EVENT_LAST, VIRTIO_F_IOMMU_PLATFORM, VIRTIO_F_VERSION_1,
};

use super::fs::VirtioFsConfig;
use super::DEFAULT_VIRTIO_FEATURES;

use fuse_backend_rs::api::filesystem::FileSystem;
use fuse_backend_rs::api::server::Server;
use fuse_backend_rs::api::{Vfs, VfsOptions};
use fuse_backend_rs::transport::FsCacheReqHandler;
use fuse_backend_rs::transport::{Reader, VirtioFsWriter};
use fuse_backend_rs::Error as FuseError;
use libc::{
    c_void, off64_t, pread64, pwrite64, rlimit, setrlimit, PROT_READ, PROT_WRITE, RLIMIT_NOFILE,
};
use seccompiler::SeccompAction;
use std::io::Error as IOError;
use virtio_queue::{Queue, QueueT};
use vm_memory::{
    Address, ByteValued, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic,
};
use vm_migration::{Migratable, Pausable, Snapshottable, Transportable};
use vm_virtio::VirtioDeviceType;
use vmm_sys_util::eventfd::EventFd;

const NUM_QUEUE_OFFSET: usize = 1;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
enum Error {
    ProcessQueue(FuseError),
    FailedSignalingUsedQueue(IOError),
    QueueReader,
    QueueWriter,
    PassthroughFs(IOError),
    Mount,
    InvalidFlags,
    MmapFailed(IOError),
    MunmapFailed(IOError),
}

impl From<Error> for IOError {
    fn from(error: Error) -> IOError {
        IOError::new(std::io::ErrorKind::Other, format!("{:?}", error))
    }
}

struct SlaveReqHandler {
    cache_offset: GuestAddress,
    cache_size: u64,
    mmap_cache_addr: u64,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
}

impl SlaveReqHandler {
    // Make sure request is within cache range
    fn is_req_valid(&self, offset: u64, len: u64) -> bool {
        let end = match offset.checked_add(len) {
            Some(n) => n,
            None => return false,
        };

        !(offset >= self.cache_size || end > self.cache_size)
    }
}

impl FsCacheReqHandler for SlaveReqHandler {
    // fn handle_config_change(&self) -> HandlerResult<u64> {
    //     debug!("handle_config_change");
    //     Ok(0)
    // }

    fn map(
        &mut self,
        foffset: u64,
        moffset: u64,
        len: u64,
        flags: u64,
        fd: RawFd,
    ) -> std::result::Result<(), IOError> {
        info!(
            "fs_slave_map foffset {:?} moffset {:?} len {} flags {} fd {}",
            foffset, moffset, len, flags, fd
        );

        let offset = moffset;
        let len = len;

        // Ignore if the length is 0.
        if len == 0 {
            return Ok(());
        }

        if !self.is_req_valid(offset, len) {
            return Err(IOError::from_raw_os_error(libc::EINVAL));
        }

        let addr = self.mmap_cache_addr + offset;
        let flags = VhostUserFSSlaveMsgFlags::from_bits(flags)
            .ok_or_else(|| IOError::from(Error::InvalidFlags))?;

        let mut prot = if (flags & VhostUserFSSlaveMsgFlags::MAP_R).bits() != 0 {
            PROT_READ
        } else {
            0
        };

        prot |= if (flags & VhostUserFSSlaveMsgFlags::MAP_W).bits() != 0 {
            PROT_WRITE
        } else {
            0
        };

        // SAFETY: FFI call with valid arguments
        let ret = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                len as usize,
                prot,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd.as_raw_fd(),
                foffset as libc::off_t,
            )
        };
        if ret == libc::MAP_FAILED {
            return Err(IOError::from(Error::MmapFailed(IOError::last_os_error())));
        }

        Ok(())
    }

    fn unmap(&mut self, requests: Vec<RemovemappingOne>) -> std::result::Result<(), IOError> {
        let riter = requests.iter();

        for request in riter {
            let offset = request.moffset;
            let mut len = request.len;

            info!("fs_slave_unmap offset {:?} len {}", offset, len);

            // Ignore if the length is 0.
            if len == 0 {
                continue;
            }

            // Need to handle a special case where the slave ask for the unmapping
            // of the entire mapping.
            if len == 0xffff_ffff_ffff_ffff {
                len = self.cache_size;
            }

            if !self.is_req_valid(offset, len) {
                return Err(IOError::from_raw_os_error(libc::EINVAL));
            }

            let addr = self.mmap_cache_addr + offset;
            // SAFETY: FFI call with valid arguments
            let ret = unsafe {
                libc::mmap(
                    addr as *mut libc::c_void,
                    len as usize,
                    libc::PROT_NONE,
                    libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            if ret == libc::MAP_FAILED {
                return Err(IOError::from(Error::MunmapFailed(IOError::last_os_error())));
            }
        }

        Ok(())
    }

    // fn sync(&self, fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
    //     debug!("fs_slave_sync");

    //     for i in 0..VHOST_USER_FS_SLAVE_ENTRIES {
    //         let offset = fs.cache_offset[i];
    //         let len = fs.len[i];

    //         // Ignore if the length is 0.
    //         if len == 0 {
    //             continue;
    //         }

    //         if !self.is_req_valid(offset, len) {
    //             return Err(IOError::from_raw_os_error(libc::EINVAL));
    //         }

    //         let addr = self.mmap_cache_addr + offset;
    //         let ret =
    //             // SAFETY: FFI call with valid arguments
    //             unsafe { libc::msync(addr as *mut libc::c_void, len as usize, libc::MS_SYNC) };
    //         if ret == -1 {
    //             return Err(IOError::last_os_error());
    //         }
    //     }

    //     Ok(0)
    // }

    fn io(
        &mut self,
        foffset: u64,
        coffset: u64,
        len: u64,
        flags: u64,
        fd: RawFd,
    ) -> std::result::Result<(), IOError> {
        info!("fs_slave_io");

        // Ignore if the length is 0.
        if len == 0 {
            return Ok(());
        }

        let mut foffset = foffset;
        let mut len = len as usize;
        let flags = VhostUserFSSlaveMsgFlags::from_bits(flags)
            .ok_or_else(|| IOError::from(Error::InvalidFlags))?;
        let gpa = coffset;
        let cache_end = self.cache_offset.raw_value() + self.cache_size;
        let efault = libc::EFAULT;

        let mut ptr = if gpa >= self.cache_offset.raw_value() && gpa < cache_end {
            let offset = gpa
                .checked_sub(self.cache_offset.raw_value())
                .ok_or_else(|| IOError::from_raw_os_error(efault))?;
            let end = gpa
                .checked_add(len as u64)
                .ok_or_else(|| IOError::from_raw_os_error(efault))?;

            if end >= cache_end {
                return Err(IOError::from_raw_os_error(efault));
            }

            self.mmap_cache_addr + offset
        } else {
            self.mem
                .memory()
                .get_host_address(GuestAddress(gpa))
                .map_err(|e| {
                    error!(
                        "Failed to find RAM region associated with guest physical address 0x{:x}: {:?}",
                        gpa, e
                    );
                    IOError::from_raw_os_error(efault)
                })? as u64
        };

        while len > 0 {
            let ret =
                if (flags & VhostUserFSSlaveMsgFlags::MAP_W) == VhostUserFSSlaveMsgFlags::MAP_W {
                    debug!("write: foffset={}, len={}", foffset, len);
                    // SAFETY: FFI call with valid arguments
                    unsafe {
                        pwrite64(
                            fd.as_raw_fd(),
                            ptr as *const c_void,
                            len,
                            foffset as off64_t,
                        )
                    }
                } else {
                    debug!("read: foffset={}, len={}", foffset, len);
                    // SAFETY: FFI call with valid arguments
                    unsafe { pread64(fd.as_raw_fd(), ptr as *mut c_void, len, foffset as off64_t) }
                };

            if ret < 0 {
                return Err(IOError::last_os_error());
            }

            if ret == 0 {
                // EOF
                return Err(IOError::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "failed to access whole buffer",
                ));
            }
            len -= ret as usize;
            foffset += ret as u64;
            ptr += ret as u64;
        }

        Ok(())
    }
}

pub struct InlineFS {
    server: Arc<Server<Arc<Vfs>>>,
    id: String,
    config: VirtioFsConfig,
    event_idx: bool,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
    iommu: bool,
    common: VirtioCommon,
    seccomp_action: SeccompAction,
    exit_evt: EventFd,
}

impl InlineFS {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        tag: &str,
        req_num_queues: usize,
        queue_size: u16,
        cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
        exit_evt: EventFd,
        seccomp_action: SeccompAction,
        iommu: bool,
        source_path: Option<String>,
        mount_path: Option<String>,
    ) -> std::io::Result<InlineFS> {
        let num_queues = NUM_QUEUE_OFFSET + req_num_queues;

        let mut config = VirtioFsConfig::default();
        let tag_bytes = tag.to_string().into_bytes();
        config.tag[..tag_bytes.len()].copy_from_slice(tag_bytes.as_slice());
        config.num_request_queues = req_num_queues as u32;

        let limit = rlimit {
            rlim_cur: 1_000_000,
            rlim_max: 1_000_000,
        };

        let ret = unsafe { setrlimit(RLIMIT_NOFILE, &limit) };

        if ret != 0 {
            return Err(IOError::new(
                std::io::ErrorKind::Other,
                format!("Failed to set rlimit {:?}", IOError::last_os_error()),
            ));
        }

        let vfs_opts = VfsOptions {
            ..VfsOptions::default()
        };
        let vfs = Arc::new(Vfs::new(vfs_opts));

        if let Some(spath) = source_path {
            let fs_cfg = Config {
                root_dir: spath,
                do_import: false,
                writeback: true,
                no_open: true,
                xattr: true,
                ..Default::default()
            };

            // TODO: Passthrough Fs needs to enlarge rlimit against host. We can exploit `MountCmd`
            // `config` field to pass such a configuration into here.
            let passthrough_fs = PassthroughFs::<()>::new(fs_cfg).map_err(Error::PassthroughFs)?;
            passthrough_fs.import().map_err(Error::PassthroughFs)?;
            info!("PassthroughFs imported");
            let fs = Box::new(passthrough_fs);

            let mpath = mount_path.unwrap_or_else(|| "/".to_string());

            vfs.mount(fs, &mpath).map_err(|_| Error::Mount)?;
        }

        // let avail_features = DEFAULT_VIRTIO_FEATURES;

        // let mut avail_protocol_features = VhostUserProtocolFeatures::MQ
        //     | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
        //     | VhostUserProtocolFeatures::REPLY_ACK
        //     | VhostUserProtocolFeatures::INFLIGHT_SHMFD
        //     | VhostUserProtocolFeatures::LOG_SHMFD;
        // let slave_protocol_features =
        //     VhostUserProtocolFeatures::SLAVE_REQ | VhostUserProtocolFeatures::SLAVE_SEND_FD;
        // if cache.is_some() {
        //     avail_protocol_features |= slave_protocol_features;
        // }

        // Filling device and vring features VMM supports.
        let mut avail_features: u64 = 1 << VIRTIO_F_VERSION_1;
        if iommu {
            avail_features |= 1 << VIRTIO_F_IOMMU_PLATFORM;
        }

        let common = VirtioCommon {
            avail_features,
            acked_features: 0,
            device_type: VirtioDeviceType::Fs as u32,
            queue_sizes: vec![queue_size; num_queues],
            paused_sync: Some(Arc::new(Barrier::new(2))),
            min_queues: 1,
            paused: Arc::new(AtomicBool::new(false)),
            ..Default::default()
        };

        Ok(InlineFS {
            common,
            seccomp_action,
            exit_evt,
            server: Arc::new(Server::new(vfs)),
            id,
            config,
            cache,
            event_idx: false,
            iommu,
            mem: None,
        })
    }
}

impl VirtioDevice for InlineFS {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value)
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data)
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_evt: Arc<dyn crate::VirtioInterrupt>,
        mut queues: Vec<(usize, virtio_queue::Queue, EventFd)>,
    ) -> crate::ActivateResult {
        self.common.activate(&queues, &interrupt_evt)?;
        self.mem = Some(mem.clone());

        let mut epoll_threads = Vec::new();
        for i in 0..queues.len() {
            let (_, queue, queue_evt) = queues.remove(0);
            let (kill_evt, pause_evt) = self.common.dup_eventfds();

            let vu_req = self.cache.as_ref().map(|c| SlaveReqHandler {
                cache_offset: c.0.addr,
                cache_size: c.0.len,
                mmap_cache_addr: c.0.host_addr,
                mem: mem.clone(),
            });

            let mut handler = FsEpollHandler {
                queue_index: i as u16,
                queue_evt,
                queue,
                mem: mem.clone(),
                interrupt_cb: interrupt_evt.clone(),
                kill_evt,
                pause_evt,
                server: self.server.clone(),
                vu_req,
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();

            spawn_virtio_thread(
                &format!("{}_q{}", self.id.clone(), i),
                &self.seccomp_action,
                Thread::VirtioVhostFs,
                &mut epoll_threads,
                &self.exit_evt,
                move || handler.run(paused, paused_sync.unwrap()),
            )?;
        }

        Ok(())
    }

    fn reset(&mut self) -> Option<Arc<dyn crate::VirtioInterrupt>> {
        None
    }

    fn get_shm_regions(&self) -> Option<VirtioSharedMemoryList> {
        self.cache.as_ref().map(|cache| cache.0.clone())
    }

    fn set_shm_regions(
        &mut self,
        shm_regions: VirtioSharedMemoryList,
    ) -> std::result::Result<(), crate::Error> {
        if let Some(mut cache) = self.cache.as_mut() {
            cache.0 = shm_regions;
            Ok(())
        } else {
            Err(crate::Error::SetShmRegionsNotSupported)
        }
    }

    fn shutdown(&mut self) {}

    fn add_memory_region(
        &mut self,
        _region: &Arc<crate::GuestRegionMmap>,
    ) -> std::result::Result<(), crate::Error> {
        Ok(())
    }

    fn userspace_mappings(&self) -> Vec<crate::UserspaceMapping> {
        let mut mappings = Vec::new();
        if let Some(cache) = self.cache.as_ref() {
            mappings.push(UserspaceMapping {
                host_addr: cache.0.host_addr,
                mem_slot: cache.0.mem_slot,
                addr: cache.0.addr,
                len: cache.0.len,
                mergeable: false,
            })
        }

        mappings
    }
}

impl Pausable for InlineFS {
    fn pause(&mut self) -> std::result::Result<(), vm_migration::MigratableError> {
        Ok(())
    }

    fn resume(&mut self) -> std::result::Result<(), vm_migration::MigratableError> {
        Ok(())
    }
}

impl Snapshottable for InlineFS {}
impl Transportable for InlineFS {}

impl Migratable for InlineFS {
    fn start_dirty_log(&mut self) -> std::result::Result<(), vm_migration::MigratableError> {
        Ok(())
    }

    fn stop_dirty_log(&mut self) -> std::result::Result<(), vm_migration::MigratableError> {
        Ok(())
    }

    fn dirty_log(
        &mut self,
    ) -> std::result::Result<vm_migration::protocol::MemoryRangeTable, vm_migration::MigratableError>
    {
        Ok(vm_migration::protocol::MemoryRangeTable::default())
    }

    fn start_migration(&mut self) -> std::result::Result<(), vm_migration::MigratableError> {
        Ok(())
    }

    fn complete_migration(&mut self) -> std::result::Result<(), vm_migration::MigratableError> {
        Ok(())
    }
}

struct FsEpollHandler<F: FileSystem + Sync> {
    queue_index: u16,
    queue_evt: EventFd,
    queue: Queue,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    server: Arc<Server<F>>,
    vu_req: Option<SlaveReqHandler>,
}

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;

impl<F: FileSystem + Sync> FsEpollHandler<F> {
    fn run(
        &mut self,
        paused: Arc<AtomicBool>,
        paused_sync: Arc<Barrier>,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;

        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }

    fn signal_used_queue(&self) -> result::Result<(), Error> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(self.queue_index))
            .map_err(|e| {
                error!("Failed to signal used queue: {:?}", e);
                Error::FailedSignalingUsedQueue(e)
            })
    }

    fn return_descriptor(queue: &mut Queue, mem: &GuestMemoryMmap, head_index: u16, len: usize) {
        let used_len: u32 = match len.try_into() {
            Ok(l) => l,
            Err(_) => panic!("Invalid used length, can't return used descritors to the ring"),
        };

        if queue.add_used(mem, head_index, used_len).is_err() {
            warn!("Couldn't return used descriptors to the ring");
        }
    }

    fn process_queue_serial(&mut self) -> Result<bool> {
        let queue = &mut self.queue;
        // let mut cache_handler = self.cache_handler.clone();
        let mut used_descs = false;

        while let Some(desc_chain) = queue.pop_descriptor_chain(self.mem.memory()) {
            let head_index = desc_chain.head_index();

            let reader = Reader::from_descriptor_chain(desc_chain.memory(), desc_chain.clone())
                .map_err(|_| Error::QueueReader)
                .unwrap();
            let writer = VirtioFsWriter::new(desc_chain.memory(), desc_chain.clone())
                .map(|w| w.into())
                .map_err(|_| Error::QueueWriter)
                .unwrap();

            info!("PROCESS_QUEUE");

            let len = self
                .server
                .handle_message(
                    reader,
                    writer,
                    self.vu_req
                        .as_mut()
                        .map(|x| x as &mut dyn FsCacheReqHandler),
                    None,
                )
                .map_err(Error::ProcessQueue)
                .unwrap();

            Self::return_descriptor(queue, desc_chain.memory(), head_index, len);
            used_descs = true;
        }

        Ok(used_descs)
    }

    fn handle_event_impl(&mut self) -> result::Result<(), EpollHelperError> {
        let needs_notification = self.process_queue_serial().map_err(|e| {
            EpollHelperError::HandleEvent(anyhow!("Failed to process queue (submit): {:?}", e))
        })?;

        if needs_notification {
            self.signal_used_queue().map_err(|e| {
                EpollHelperError::HandleEvent(anyhow!("Failed to signal used queue: {:?}", e))
            })?
        };

        Ok(())
    }
}

impl<F: FileSystem + Sync> EpollHelperHandler for FsEpollHandler<F> {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            QUEUE_AVAIL_EVENT => {
                info!("QUEUE EVT");
                self.queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {:?}", e))
                })?;
                self.handle_event_impl()?
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unexpected event: {}",
                    ev_type
                )));
            }
        }
        Ok(())
    }
}

// impl VhostUserBackendMut<VringRwLock<GuestMemoryAtomic<GuestMemoryMmap>>, AtomicBitmap>
//     for InlineFS
// {
//     fn num_queues(&self) -> usize {
//         self.backend.lock().unwrap().config.num_request_queues as usize
//     }

//     fn max_queue_size(&self) -> usize {
//         QUEUE_SIZE
//     }

//     fn features(&self) -> u64 {
//         1 << VIRTIO_F_VERSION_1
//             | 1 << VIRTIO_RING_F_INDIRECT_DESC
//             | 1 << VIRTIO_RING_F_EVENT_IDX
//             | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
//     }

//     fn protocol_features(&self) -> vhost::vhost_user::VhostUserProtocolFeatures {
//         VhostUserProtocolFeatures::MQ
//             | VhostUserProtocolFeatures::SLAVE_REQ
//             | VhostUserProtocolFeatures::SLAVE_SEND_FD
//             | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
//             | VhostUserProtocolFeatures::LOG_SHMFD
//             | VhostUserProtocolFeatures::REPLY_ACK
//     }

//     fn set_event_idx(&mut self, enabled: bool) {
//         self.backend.lock().unwrap().event_idx = enabled;
//     }

//     fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> std::io::Result<()> {
//         self.backend.lock().unwrap().mem = Some(mem);
//         Ok(())
//     }

//     fn handle_event(
//         &mut self,
//         device_event: u16,
//         evset: EventSet,
//         vrings: &[VringRwLock<GuestMemoryAtomic<GuestMemoryMmap>>],
//         thread_id: usize,
//     ) -> std::io::Result<bool> {
//         if evset != EventSet::IN {
//             return Err(Error::HandleEventNotEpollIn.into());
//         }

//         let mut vring_state = if (device_event as usize) < vrings.len() {
//             debug!("QUEUE EVENT: queueIdx {}", device_event);
//             vrings[device_event as usize].get_mut()
//         } else {
//             return Err(Error::HandleEventUnknownEvent.into());
//         };

//         if self.backend.lock().unwrap().event_idx {
//             loop {
//                 vring_state.disable_notification().unwrap();
//                 self.backend
//                     .lock()
//                     .unwrap()
//                     .process_queue(&mut vring_state)?;
//                 if !vring_state.enable_notification().unwrap() {
//                     break;
//                 }
//             }
//         } else {
//             self.backend
//                 .lock()
//                 .unwrap()
//                 .process_queue(&mut vring_state)?;
//         }

//         Ok(false)
//     }
// }
