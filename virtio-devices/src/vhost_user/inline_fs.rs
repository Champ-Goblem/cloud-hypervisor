use anyhow::anyhow;
use fuse_backend_rs::passthrough::{Config, PassthroughFs};
use std::os::unix::prelude::AsRawFd;
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Mutex, RwLockWriteGuard};

use crate::seccomp_filters::Thread;
use crate::thread_helper::spawn_virtio_thread;
use crate::{
    EpollHelper, EpollHelperError, EpollHelperHandler, GuestMemoryMmap, MmapRegion, VirtioCommon,
    VirtioDevice, VirtioInterrupt, VirtioInterruptType, VirtioSharedMemoryList,
    EPOLL_HELPER_EVENT_LAST, VIRTIO_F_IOMMU_PLATFORM, VIRTIO_F_VERSION_1,
};

use super::fs::VirtioFsConfig;
use super::{VhostUserCommon, DEFAULT_VIRTIO_FEATURES};

use fuse_backend_rs::api::filesystem::FileSystem;
use fuse_backend_rs::api::server::Server;
use fuse_backend_rs::api::{Vfs, VfsOptions};
use fuse_backend_rs::transport::{Error as FuseTransportError, FsCacheReqHandler};
use fuse_backend_rs::transport::{Reader, VirtioFsWriter};
use fuse_backend_rs::Error as FuseError;
use seccompiler::SeccompAction;
use vhost_user_backend::VringState;
use virtio_bindings::virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC};
use virtio_queue::{Queue, QueueT};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{ByteValued, GuestAddressSpace, GuestMemoryAtomic};
use vm_migration::{Migratable, Pausable, Snapshottable, Transportable};
use vm_virtio::VirtioDeviceType;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

const NUM_QUEUE_OFFSET: usize = 1;
const QUEUE_SIZE: usize = 1024;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
enum Error {
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
    /// Failed to handle event other than input event.
    HandleEventNotEpollIn,
    /// Failed to iterate over the queue
    IterateQueue,
    InvalidDescriptorChain(FuseTransportError),
    ProcessQueue(FuseError),
    FailedSignalingUsedQueue(std::io::Error),
    QueueReader,
    QueueWriter,
    PassthroughFs(std::io::Error),
    MountError,
}

impl From<Error> for std::io::Error {
    fn from(error: Error) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", error))
    }
}
pub struct InlineFSDaxHandler {}

impl FsCacheReqHandler for InlineFSDaxHandler {
    fn map(
        &mut self,
        foffset: u64,
        moffset: u64,
        len: u64,
        flags: u64,
        fd: std::os::unix::prelude::RawFd,
    ) -> std::io::Result<()> {
        info!("Map request");
        todo!()
    }

    fn unmap(
        &mut self,
        requests: Vec<fuse_backend_rs::abi::virtio_fs::RemovemappingOne>,
    ) -> std::io::Result<()> {
        info!("Unmap request");
        todo!()
    }
}

pub struct InlineFSHandler {
    server: Arc<Server<Arc<Vfs>>>,
    id: String,
    config: VirtioFsConfig,
    event_idx: bool,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    vu_req: Option<InlineFSDaxHandler>,
    cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
    iommu: bool,
}

impl InlineFSHandler {
    fn process_queue(
        &mut self,
        vring_state: &mut RwLockWriteGuard<VringState<GuestMemoryAtomic<GuestMemoryMmap>>>,
    ) -> Result<bool> {
        let mut used_any = false;

        while let Some(chain) = vring_state
            .get_queue_mut()
            .pop_descriptor_chain(self.mem.as_ref().unwrap().memory())
        {
            used_any = true;

            let head_index = chain.head_index();
            let mem = chain.memory();

            let reader = Reader::from_descriptor_chain(mem, chain.clone())
                .map_err(Error::InvalidDescriptorChain)?;
            let writer = VirtioFsWriter::new(mem, chain.clone())
                .map(|w| w.into())
                .map_err(Error::InvalidDescriptorChain)?;

            self.server
                .handle_message(
                    reader,
                    writer,
                    self.vu_req
                        .as_mut()
                        .map(|x| x as &mut dyn FsCacheReqHandler),
                    None,
                )
                .map_err(Error::ProcessQueue)?;

            if self.event_idx {
                if vring_state.add_used(head_index, 0).is_err() {
                    warn!("Couldn't return used descriptors to the ring");
                }

                match vring_state.needs_notification() {
                    Err(_) => {
                        warn!("Couldn't check if queue needs to be notified");
                        vring_state.signal_used_queue().unwrap();
                    }
                    Ok(needs_notification) => {
                        if needs_notification {
                            vring_state.signal_used_queue().unwrap();
                        }
                    }
                }
            } else {
                if vring_state.add_used(head_index, 0).is_err() {
                    warn!("Couldn't return used descriptors to the ring");
                }
                vring_state.signal_used_queue().unwrap();
            }
        }

        Ok(used_any)
    }
}

pub struct InlineFS {
    backend: Mutex<InlineFSHandler>,
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
    ) -> std::io::Result<InlineFS> {
        let num_queues = NUM_QUEUE_OFFSET + req_num_queues;

        let mut config = VirtioFsConfig::default();
        let tag_bytes = tag.to_string().into_bytes();
        config.tag[..tag_bytes.len()].copy_from_slice(tag_bytes.as_slice());
        config.num_request_queues = req_num_queues as u32;

        let vfs_opts = VfsOptions {
            ..VfsOptions::default()
        };
        let vfs = Arc::new(Vfs::new(vfs_opts));

        let fs_cfg = Config {
            root_dir: "/tmp/inlinefs".to_string(),
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

        vfs.mount(fs, "/").map_err(|_| Error::MountError)?;

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

        let fs = InlineFSHandler {
            server: Arc::new(Server::new(vfs)),
            id,
            config,
            cache,
            event_idx: false,
            iommu,
            mem: None,
            vu_req: None,
        };

        Ok(InlineFS {
            backend: Mutex::new(fs),
            common,
            seccomp_action,
            exit_evt,
        })
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
        let backend = self.backend.lock().unwrap();
        self.read_config_from_slice(backend.config.as_slice(), offset, data)
    }

    fn activate(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        interrupt_evt: Arc<dyn crate::VirtioInterrupt>,
        mut queues: Vec<(usize, virtio_queue::Queue, EventFd)>,
    ) -> crate::ActivateResult {
        self.common.activate(&queues, &interrupt_evt)?;
        let mut backend = self.backend.lock().unwrap();
        backend.mem = Some(mem.clone());

        let mut epoll_threads = Vec::new();
        for i in 0..queues.len() {
            let (_, queue, queue_evt) = queues.remove(0);
            let (kill_evt, pause_evt) = self.common.dup_eventfds();

            let mut handler = FsEpollHandler {
                queue_index: i as u16,
                queue_evt,
                queue,
                mem: mem.clone(),
                interrupt_cb: interrupt_evt.clone(),
                kill_evt,
                pause_evt,
                server: backend.server.clone(),
                // cache_handler,
            };

            let paused = self.common.paused.clone();
            let paused_sync = self.common.paused_sync.clone();

            spawn_virtio_thread(
                &format!("{}_q{}", backend.id.clone(), i),
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
        None
    }

    fn set_shm_regions(
        &mut self,
        _shm_regions: VirtioSharedMemoryList,
    ) -> std::result::Result<(), crate::Error> {
        std::unimplemented!()
    }

    fn shutdown(&mut self) {}

    fn add_memory_region(
        &mut self,
        _region: &Arc<crate::GuestRegionMmap>,
    ) -> std::result::Result<(), crate::Error> {
        Ok(())
    }

    fn userspace_mappings(&self) -> Vec<crate::UserspaceMapping> {
        Vec::new()
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
    // cache_handler: Option<CacheHandler>,
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
                .handle_message(reader, writer, None, None)
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
