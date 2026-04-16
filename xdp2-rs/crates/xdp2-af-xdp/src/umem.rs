//! UMEM -- contiguous shared memory for AF_XDP packet buffers.
//!
//! A UMEM is a region of contiguous, page-aligned memory divided into
//! fixed-size frames. Each frame holds one packet. The kernel and userspace
//! share this memory: the kernel writes received packets into frames, and
//! userspace reads them directly -- zero copy.
//!
//! Frame addresses are `frame_index * frame_size`, enabling predictable
//! memory access patterns that benefit cache prefetching and SIMD gathers.

use std::io;
use std::ptr;

/// Configuration for UMEM allocation.
pub struct UmemConfig {
    /// Size of each frame in bytes (typically 4096).
    pub frame_size: u32,
    /// Number of frames to allocate.
    pub frame_count: u32,
    /// Per-frame headroom in bytes (reserved space before packet data).
    pub headroom: u32,
    /// Use 2MB huge pages for the UMEM region.
    ///
    /// Reduces TLB misses for large UMEM sizes (32MB+ = 8192 frames).
    /// Requires huge pages configured on the system:
    ///   `echo 64 > /proc/sys/vm/nr_hugepages`
    /// Falls back to normal pages if huge pages are unavailable.
    pub huge_pages: bool,
}

impl Default for UmemConfig {
    fn default() -> Self {
        Self {
            frame_size: 4096,
            frame_count: 4096,
            headroom: 0,
            huge_pages: false,
        }
    }
}

/// A UMEM region: contiguous mmap'd memory shared between kernel and userspace.
pub struct Umem {
    base: *mut u8,
    len: usize,
    frame_size: u32,
    frame_count: u32,
    /// Pool of free frame addresses available for the fill ring.
    free_frames: Vec<u64>,
}

// Safety: The mmap'd region is process-wide shared memory. Concurrent access
// is synchronized through the fill/completion ring protocol -- the kernel only
// writes to frames that userspace has submitted via the fill ring, and
// userspace only reads frames that the kernel has delivered via the RX ring.
unsafe impl Send for Umem {}
unsafe impl Sync for Umem {}

impl Umem {
    /// Allocate a UMEM region via `mmap(2)`.
    ///
    /// Uses `MAP_POPULATE` to fault pages in immediately, avoiding TLB misses
    /// on the hot path.
    pub fn new(config: &UmemConfig) -> io::Result<Self> {
        let len = config.frame_size as usize * config.frame_count as usize;

        let mut flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE;
        if config.huge_pages {
            flags |= libc::MAP_HUGETLB;
        }

        // SAFETY: mmap with MAP_ANONYMOUS creates a new private mapping.
        let mut base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            )
        };

        // Fall back to normal pages if huge pages fail.
        if base == libc::MAP_FAILED && config.huge_pages {
            base = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                    -1,
                    0,
                )
            };
        }

        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        // All frames start as free.
        let free_frames: Vec<u64> = (0..config.frame_count)
            .map(|i| i as u64 * config.frame_size as u64)
            .collect();

        Ok(Self {
            base: base as *mut u8,
            len,
            frame_size: config.frame_size,
            frame_count: config.frame_count,
            free_frames,
        })
    }

    /// Base pointer of the UMEM region.
    pub fn base(&self) -> *mut u8 {
        self.base
    }

    /// Total length of the UMEM region in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Frame size in bytes.
    pub fn frame_size(&self) -> u32 {
        self.frame_size
    }

    /// Number of frames in the UMEM.
    pub fn frame_count(&self) -> u32 {
        self.frame_count
    }

    /// Get a packet slice from a UMEM address and length.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `addr + len` is within UMEM bounds
    /// - The frame has been received from the RX ring and not yet recycled
    ///   (i.e., the kernel is not concurrently writing to this frame)
    pub unsafe fn pkt(&self, addr: u64, len: u32) -> &[u8] {
        let ptr = self.base.add(addr as usize);
        std::slice::from_raw_parts(ptr, len as usize)
    }

    /// Pop a free frame address from the pool. Returns `None` if empty.
    pub fn alloc_frame(&mut self) -> Option<u64> {
        self.free_frames.pop()
    }

    /// Return a frame address to the free pool.
    pub fn free_frame(&mut self, addr: u64) {
        self.free_frames.push(addr);
    }

    /// Number of free frames available.
    pub fn free_count(&self) -> usize {
        self.free_frames.len()
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        // SAFETY: We mmap'd this region in new() and own it.
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, self.len);
        }
    }
}
