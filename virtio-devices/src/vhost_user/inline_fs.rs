use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Barrier, Mutex, RwLockWriteGuard};

use crate::{
    GuestMemoryMmap, MmapRegion, VirtioCommon, VirtioSharedMemoryList, VIRTIO_F_VERSION_1,
};

use super::fs::VirtioFsConfig;
use super::{VhostUserCommon, DEFAULT_VIRTIO_FEATURES};

use fuse_backend_rs::api::server::Server;
use fuse_backend_rs::api::{Vfs, VfsOptions};
use fuse_backend_rs::transport::{Error as FuseTransportError, FsCacheReqHandler};
use fuse_backend_rs::transport::{Reader, VirtioFsWriter};
use fuse_backend_rs::Error as FuseError;
use seccompiler::SeccompAction;
use vhost::vhost_user::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringState, VringT};
use virtio_bindings::virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC};
use virtio_queue::QueueT;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic};
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
        debug!("Map request");
        todo!()
    }

    fn unmap(
        &mut self,
        requests: Vec<fuse_backend_rs::abi::virtio_fs::RemovemappingOne>,
    ) -> std::io::Result<()> {
        debug!("Unmap request");
        todo!()
    }
}

pub struct InlineFSHandler {
    server: Arc<Server<Arc<Vfs>>>,
    common: VirtioCommon,
    id: String,
    config: VirtioFsConfig,
    event_idx: bool,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    vu_req: Option<InlineFSDaxHandler>,
    cache: Option<(VirtioSharedMemoryList, MmapRegion)>,
    exit_evt: EventFd,
    iommu: bool,
}

impl InlineFSHandler {
    fn process_queue(
        &mut self,
        vring_state: &mut RwLockWriteGuard<VringState<GuestMemoryAtomic<GuestMemoryMmap>>>,
    ) -> Result<bool> {
        let mut used_any = false;

        while let Some(mut chain) = vring_state
            .get_queue_mut()
            .pop_descriptor_chain(self.mem.memory())
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
        iommu: bool,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
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

        let avail_features = DEFAULT_VIRTIO_FEATURES;

        let mut avail_protocol_features = VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
            | VhostUserProtocolFeatures::REPLY_ACK
            | VhostUserProtocolFeatures::INFLIGHT_SHMFD
            | VhostUserProtocolFeatures::LOG_SHMFD;
        let slave_protocol_features =
            VhostUserProtocolFeatures::SLAVE_REQ | VhostUserProtocolFeatures::SLAVE_SEND_FD;
        if cache.is_some() {
            avail_protocol_features |= slave_protocol_features;
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
            common,
            id,
            config,
            cache,
            event_idx: false,
            iommu,
            mem,
            vu_req: None,
            exit_evt,
        };

        Ok(InlineFS {
            backend: Mutex::new(fs),
        })
    }
}

impl VhostUserBackendMut<VringRwLock<GuestMemoryAtomic<GuestMemoryMmap>>, AtomicBitmap>
    for InlineFS
{
    fn num_queues(&self) -> usize {
        self.backend.lock().unwrap().config.num_request_queues as usize
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> vhost::vhost_user::VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::SLAVE_REQ
            | VhostUserProtocolFeatures::SLAVE_SEND_FD
            | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
            | VhostUserProtocolFeatures::LOG_SHMFD
            | VhostUserProtocolFeatures::REPLY_ACK
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.backend.lock().unwrap().event_idx = enabled;
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> std::io::Result<()> {
        self.backend.lock().unwrap().mem = mem;
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock<GuestMemoryAtomic<GuestMemoryMmap>>],
        thread_id: usize,
    ) -> std::io::Result<bool> {
        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        let mut vring_state = if (device_event as usize) < vrings.len() {
            debug!("QUEUE EVENT: queueIdx {}", device_event);
            vrings[device_event as usize].get_mut()
        } else {
            return Err(Error::HandleEventUnknownEvent.into());
        };

        if self.backend.lock().unwrap().event_idx {
            loop {
                vring_state.disable_notification().unwrap();
                self.backend
                    .lock()
                    .unwrap()
                    .process_queue(&mut vring_state)?;
                if !vring_state.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            self.backend
                .lock()
                .unwrap()
                .process_queue(&mut vring_state)?;
        }

        Ok(false)
    }
}
