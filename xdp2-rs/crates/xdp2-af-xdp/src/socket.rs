//! AF_XDP socket creation, ring mapping, and bind.
//!
//! An `XskSocket` encapsulates the full lifecycle of an AF_XDP socket:
//! socket creation, UMEM registration, ring buffer mmap, and binding to
//! a specific network interface and RX queue.

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::atomic::{fence, Ordering};

use crate::sys::*;
use crate::umem::Umem;
use crate::{Config, Error};

/// A memory-mapped ring buffer shared between kernel and userspace.
///
/// Rings are producer/consumer queues. For each ring, one side (kernel or
/// userspace) is the producer and the other is the consumer:
///
/// - **Fill ring**: userspace produces (empty frames), kernel consumes
/// - **Completion ring**: kernel produces (TX'd frames), userspace consumes
/// - **RX ring**: kernel produces (received packets), userspace consumes
/// - **TX ring**: userspace produces (packets to send), kernel consumes
pub(crate) struct Ring {
    /// Base address of the mmap'd ring region.
    map_addr: *mut u8,
    /// Total size of the mmap'd region (for munmap).
    map_len: usize,
    /// Pointer to the producer counter in shared memory.
    producer: *mut u32,
    /// Pointer to the consumer counter in shared memory.
    consumer: *mut u32,
    /// Pointer to the flags field in shared memory.
    flags: *mut u32,
    /// Pointer to the start of the descriptor array.
    descs: *mut u8,
    /// Ring size (number of entries, must be power of 2).
    pub(crate) size: u32,
    /// Mask for index wrapping (`size - 1`).
    mask: u32,
    /// Locally cached producer value (reduces shared memory reads).
    pub(crate) cached_prod: u32,
    /// Locally cached consumer value (reduces shared memory reads).
    /// For producer rings: initialized to `size` (i.e., `consumer + size`).
    pub(crate) cached_cons: u32,
}

unsafe impl Send for Ring {}

impl Ring {
    /// Map a ring from the socket file descriptor.
    ///
    /// `is_producer`: true for rings where userspace is the producer (Fill, TX).
    /// This affects the initial `cached_cons` value.
    fn map(
        fd: RawFd,
        offsets: &XdpRingOffset,
        ring_size: u32,
        entry_size: usize,
        pgoff: u64,
        is_producer: bool,
    ) -> io::Result<Self> {
        let map_len = offsets.desc as usize + ring_size as usize * entry_size;

        // SAFETY: We mmap the kernel-allocated ring buffer via the socket fd.
        let map_addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                pgoff as libc::off_t,
            )
        };

        if map_addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        let base = map_addr as *mut u8;

        Ok(Self {
            map_addr: base,
            map_len,
            // SAFETY: Offsets come from the kernel via XDP_MMAP_OFFSETS.
            producer: unsafe { base.add(offsets.producer as usize) as *mut u32 },
            consumer: unsafe { base.add(offsets.consumer as usize) as *mut u32 },
            flags: unsafe { base.add(offsets.flags as usize) as *mut u32 },
            descs: unsafe { base.add(offsets.desc as usize) },
            size: ring_size,
            mask: ring_size - 1,
            cached_prod: 0,
            // Producer rings cache consumer + size to simplify free-space math.
            cached_cons: if is_producer { ring_size } else { 0 },
        })
    }

    // ---- Shared memory access with proper ordering ----

    /// Read the producer counter with acquire semantics.
    fn load_producer(&self) -> u32 {
        // SAFETY: Producer pointer is within the mmap'd region.
        let val = unsafe { ptr::read_volatile(self.producer) };
        fence(Ordering::Acquire);
        val
    }

    /// Read the consumer counter with acquire semantics.
    fn load_consumer(&self) -> u32 {
        // SAFETY: Consumer pointer is within the mmap'd region.
        let val = unsafe { ptr::read_volatile(self.consumer) };
        fence(Ordering::Acquire);
        val
    }

    /// Write the producer counter with release semantics.
    fn store_producer(&self, val: u32) {
        fence(Ordering::Release);
        // SAFETY: Producer pointer is within the mmap'd region.
        unsafe { ptr::write_volatile(self.producer, val) };
    }

    /// Write the consumer counter with release semantics.
    fn store_consumer(&self, val: u32) {
        fence(Ordering::Release);
        // SAFETY: Consumer pointer is within the mmap'd region.
        unsafe { ptr::write_volatile(self.consumer, val) };
    }

    // ---- Consumer operations (RX ring, Completion ring) ----

    /// Number of entries available for consumption.
    pub(crate) fn cons_available(&mut self) -> u32 {
        let entries = self.cached_prod.wrapping_sub(self.cached_cons);
        if entries > 0 {
            return entries;
        }
        // Refresh cached producer from shared memory.
        self.cached_prod = self.load_producer();
        self.cached_prod.wrapping_sub(self.cached_cons)
    }

    /// Release consumed entries (advance the consumer counter).
    pub(crate) fn cons_release(&mut self, count: u32) {
        self.cached_cons = self.cached_cons.wrapping_add(count);
        self.store_consumer(self.cached_cons);
    }

    // ---- Producer operations (Fill ring, TX ring) ----

    /// Number of free slots available for production.
    pub(crate) fn prod_free(&mut self) -> u32 {
        let free = self.cached_cons.wrapping_sub(self.cached_prod);
        if free > 0 {
            return free;
        }
        // Refresh: consumer + size (see kernel xsk_prod_nb_free).
        self.cached_cons = self.load_consumer().wrapping_add(self.size);
        self.cached_cons.wrapping_sub(self.cached_prod)
    }

    /// Submit produced entries (advance the producer counter).
    pub(crate) fn prod_submit(&mut self, count: u32) {
        self.cached_prod = self.cached_prod.wrapping_add(count);
        self.store_producer(self.cached_prod);
    }

    // ---- Descriptor access ----

    /// Read an `XdpDesc` at the given ring index (for RX/TX rings).
    pub(crate) fn desc(&self, idx: u32) -> XdpDesc {
        // SAFETY: idx is masked to ring bounds; descs points to XdpDesc array.
        unsafe {
            let ptr = self.descs as *const XdpDesc;
            ptr.add((idx & self.mask) as usize).read()
        }
    }

    /// Read a frame address at the given ring index (for Fill/Completion rings).
    #[allow(dead_code)]
    pub(crate) fn addr(&self, idx: u32) -> u64 {
        // SAFETY: idx is masked to ring bounds; descs points to u64 array.
        unsafe {
            let ptr = self.descs as *const u64;
            ptr.add((idx & self.mask) as usize).read()
        }
    }

    /// Write a frame address at the given ring index (for Fill ring).
    pub(crate) fn set_addr(&self, idx: u32, addr: u64) {
        // SAFETY: idx is masked to ring bounds; descs points to u64 array.
        unsafe {
            let ptr = self.descs as *mut u64;
            ptr.add((idx & self.mask) as usize).write(addr);
        }
    }

    /// Check the NEED_WAKEUP flag (used with `XDP_USE_NEED_WAKEUP`).
    pub(crate) fn needs_wakeup(&self) -> bool {
        // SAFETY: flags pointer is within the mmap'd region.
        let val = unsafe { ptr::read_volatile(self.flags) };
        val & XDP_RING_NEED_WAKEUP != 0
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        if !self.map_addr.is_null() {
            // SAFETY: We mmap'd this region in Ring::map().
            unsafe {
                libc::munmap(self.map_addr as *mut libc::c_void, self.map_len);
            }
        }
    }
}

// ---- XskSocket ----

/// An AF_XDP socket bound to a network interface and RX queue.
///
/// Owns the UMEM, fill ring, completion ring, and RX ring.
/// Provides zero-copy packet reception via the RX ring.
pub struct XskSocket {
    pub(crate) fd: OwnedFd,
    pub(crate) umem: Umem,
    pub(crate) rx_ring: Ring,
    pub(crate) fill_ring: Ring,
    pub(crate) comp_ring: Ring,
}

impl XskSocket {
    /// Create an AF_XDP socket, register UMEM, map rings, and bind to
    /// the given interface and queue.
    ///
    /// The fill ring is populated with initial frames so the socket is
    /// immediately ready to receive packets.
    pub fn bind(ifname: &str, queue_id: u32, config: Config) -> Result<Self, Error> {
        // Validate ring sizes (must be powers of 2).
        for &size in &[
            config.socket.rx_ring_size,
            config.socket.fill_ring_size,
            config.socket.comp_ring_size,
        ] {
            if !size.is_power_of_two() {
                return Err(Error::InvalidRingSize(size));
            }
        }

        // Allocate UMEM.
        let umem = Umem::new(&config.umem)?;

        // Create AF_XDP socket.
        // SAFETY: Standard socket(2) call.
        let raw_fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: raw_fd is a valid, newly created file descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let rfd = fd.as_raw_fd();

        // Register UMEM with the kernel.
        let reg = XdpUmemReg {
            addr: umem.base() as u64,
            len: umem.len() as u64,
            chunk_size: umem.frame_size(),
            headroom: config.umem.headroom,
            flags: 0,
        };
        setsockopt(rfd, XDP_UMEM_REG, &reg)?;

        // Configure ring sizes.
        setsockopt(rfd, XDP_UMEM_FILL_RING, &config.socket.fill_ring_size)?;
        setsockopt(rfd, XDP_UMEM_COMPLETION_RING, &config.socket.comp_ring_size)?;
        setsockopt(rfd, XDP_RX_RING, &config.socket.rx_ring_size)?;

        // Retrieve mmap offsets for all rings.
        let offsets = get_mmap_offsets(rfd)?;

        // Map the rings.
        let rx_ring = Ring::map(
            rfd,
            &offsets.rx,
            config.socket.rx_ring_size,
            mem::size_of::<XdpDesc>(),
            XDP_PGOFF_RX_RING,
            false, // userspace is consumer
        )?;
        let fill_ring = Ring::map(
            rfd,
            &offsets.fr,
            config.socket.fill_ring_size,
            mem::size_of::<u64>(),
            XDP_UMEM_PGOFF_FILL_RING,
            true, // userspace is producer
        )?;
        let comp_ring = Ring::map(
            rfd,
            &offsets.cr,
            config.socket.comp_ring_size,
            mem::size_of::<u64>(),
            XDP_UMEM_PGOFF_COMPLETION_RING,
            false, // userspace is consumer
        )?;

        // Resolve interface name to index.
        let ifindex = if_nametoindex(ifname)?;

        // Bind to interface + queue.
        let addr = SockaddrXdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: config.socket.bind_flags,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: 0,
        };
        // SAFETY: addr is a valid sockaddr_xdp.
        let ret = unsafe {
            libc::bind(
                rfd,
                &addr as *const SockaddrXdp as *const libc::sockaddr,
                mem::size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error().into());
        }

        let mut sock = Self {
            fd,
            umem,
            rx_ring,
            fill_ring,
            comp_ring,
        };

        // Populate the fill ring so the kernel has frames to receive into.
        sock.fill_initial();

        Ok(sock)
    }

    /// Populate the fill ring with free frames from the UMEM pool.
    fn fill_initial(&mut self) -> usize {
        let space = self.fill_ring.prod_free() as usize;
        let count = self.umem.free_count().min(space);
        if count == 0 {
            return 0;
        }

        let start = self.fill_ring.cached_prod;
        for i in 0..count {
            let addr = self.umem.alloc_frame().unwrap();
            self.fill_ring.set_addr(start + i as u32, addr);
        }
        self.fill_ring.prod_submit(count as u32);
        count
    }

    /// The raw file descriptor (for `poll(2)` integration).
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Register this socket in a pinned XSKMAP BPF map.
    ///
    /// The XDP program uses this map to redirect packets to AF_XDP sockets.
    /// `xskmap_path` is the pinned map path, typically `/sys/fs/bpf/xsks_map`.
    /// `queue_id` is the map key (the RX queue this socket is bound to).
    ///
    /// Requires `CAP_BPF` or root.
    pub fn register_xskmap(&self, xskmap_path: &str, queue_id: u32) -> io::Result<()> {
        let map_fd = bpf_obj_get(xskmap_path)?;
        let xsk_fd = self.fd.as_raw_fd() as u32;
        let result = bpf_map_update(map_fd, &queue_id, &xsk_fd);
        // SAFETY: map_fd was opened by bpf_obj_get.
        unsafe { libc::close(map_fd) };
        result
    }
}

// ---- Helper functions ----

/// Resolve a network interface name to its index.
fn if_nametoindex(name: &str) -> Result<u32, Error> {
    let cname = CString::new(name).map_err(|_| Error::InterfaceNotFound(name.to_string()))?;
    // SAFETY: cname is a valid null-terminated C string.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        Err(Error::InterfaceNotFound(name.to_string()))
    } else {
        Ok(idx)
    }
}

/// Set a socket option with an arbitrary value.
fn setsockopt<T>(fd: RawFd, opt: i32, val: &T) -> io::Result<()> {
    // SAFETY: val is a valid reference to T, size_of::<T>() is correct.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_XDP,
            opt,
            val as *const T as *const libc::c_void,
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Get the mmap offsets for all rings.
fn get_mmap_offsets(fd: RawFd) -> io::Result<XdpMmapOffsets> {
    let mut offsets = XdpMmapOffsets::default();
    let mut len = mem::size_of::<XdpMmapOffsets>() as libc::socklen_t;
    // SAFETY: offsets is a valid XdpMmapOffsets, len is its size.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS,
            &mut offsets as *mut XdpMmapOffsets as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(offsets)
    }
}

// ---- BPF syscall helpers (for XSKMAP registration) ----

const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
const BPF_OBJ_GET: libc::c_long = 7;
const BPF_ANY: u64 = 0;

/// Open a pinned BPF object by path. Returns its file descriptor.
fn bpf_obj_get(path: &str) -> io::Result<RawFd> {
    let cpath = CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid BPF path"))?;

    // BPF_OBJ_GET attr layout: { pathname: u64, bpf_fd: u32, file_flags: u32 }
    #[repr(C)]
    struct Attr {
        pathname: u64,
        bpf_fd: u32,
        file_flags: u32,
    }

    let attr = Attr {
        pathname: cpath.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };

    // SAFETY: attr is valid for the BPF_OBJ_GET command.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET,
            &attr as *const Attr,
            mem::size_of::<Attr>(),
        )
    };

    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd as RawFd)
    }
}

/// Update an element in a BPF map.
fn bpf_map_update(map_fd: RawFd, key: &u32, value: &u32) -> io::Result<()> {
    // BPF_MAP_UPDATE_ELEM attr layout:
    // { map_fd: u32, _pad: u32, key: u64, value: u64, flags: u64 }
    #[repr(C)]
    struct Attr {
        map_fd: u32,
        _pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    let attr = Attr {
        map_fd: map_fd as u32,
        _pad: 0,
        key: key as *const u32 as u64,
        value: value as *const u32 as u64,
        flags: BPF_ANY,
    };

    // SAFETY: attr is valid for the BPF_MAP_UPDATE_ELEM command.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_UPDATE_ELEM,
            &attr as *const Attr,
            mem::size_of::<Attr>(),
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
