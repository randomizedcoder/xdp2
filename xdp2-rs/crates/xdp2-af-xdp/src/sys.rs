//! AF_XDP kernel ABI constants and structures.
//!
//! These match `include/uapi/linux/if_xdp.h` in the Linux kernel.

// ---- Address family and socket level ----

pub const AF_XDP: i32 = 44;
pub const SOL_XDP: i32 = 283;

// ---- Socket options (setsockopt / getsockopt) ----

pub const XDP_MMAP_OFFSETS: i32 = 1;
pub const XDP_RX_RING: i32 = 2;
pub const XDP_TX_RING: i32 = 3;
pub const XDP_UMEM_REG: i32 = 4;
pub const XDP_UMEM_FILL_RING: i32 = 5;
pub const XDP_UMEM_COMPLETION_RING: i32 = 6;

// ---- mmap page offsets for ring mapping ----

pub const XDP_PGOFF_RX_RING: u64 = 0;
pub const XDP_PGOFF_TX_RING: u64 = 0x8000_0000;
pub const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x1_0000_0000;
pub const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x1_8000_0000;

// ---- Bind flags (sockaddr_xdp.sxdp_flags) ----

pub const XDP_SHARED_UMEM: u16 = 1 << 0;
pub const XDP_COPY: u16 = 1 << 1;
pub const XDP_ZEROCOPY: u16 = 1 << 2;
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

// ---- Ring flags ----

pub const XDP_RING_NEED_WAKEUP: u32 = 1 << 0;

// ---- Kernel structures ----

/// UMEM registration parameters (matches `struct xdp_umem_reg`).
#[repr(C)]
pub struct XdpUmemReg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

/// Packet descriptor in RX/TX rings (matches `struct xdp_desc`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

/// Byte offsets within a mapped ring region (matches `struct xdp_ring_offset`).
#[repr(C)]
#[derive(Default)]
pub struct XdpRingOffset {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

/// All ring offsets returned by `XDP_MMAP_OFFSETS` (matches `struct xdp_mmap_offsets`).
#[repr(C)]
#[derive(Default)]
pub struct XdpMmapOffsets {
    pub rx: XdpRingOffset,
    pub tx: XdpRingOffset,
    pub fr: XdpRingOffset,
    pub cr: XdpRingOffset,
}

/// AF_XDP socket address (matches `struct sockaddr_xdp`).
#[repr(C)]
pub struct SockaddrXdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}
