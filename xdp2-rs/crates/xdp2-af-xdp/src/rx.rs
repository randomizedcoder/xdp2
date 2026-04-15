//! RX path -- receive packets from the AF_XDP socket.
//!
//! This module implements the hot-path operations:
//! - `recv`: read a batch of packet descriptors from the RX ring
//! - `recycle`: return processed frames to the fill ring for reuse
//! - `poll`: wait for RX activity (when the RX ring is empty)

use std::io;
use std::os::unix::io::AsRawFd;

use crate::socket::XskSocket;
use crate::sys::XdpDesc;

impl XskSocket {
    /// Receive a batch of packet descriptors from the RX ring.
    ///
    /// Returns the number of descriptors written to `batch`.
    /// Returns 0 if no packets are available (non-blocking).
    ///
    /// After processing each packet, call [`recycle`] to return the frames
    /// to the fill ring so the kernel can reuse them for new packets.
    pub fn recv(&mut self, batch: &mut [XdpDesc]) -> usize {
        let available = self.rx_ring.cons_available();
        let n = available.min(batch.len() as u32);
        if n == 0 {
            return 0;
        }

        let start = self.rx_ring.cached_cons;
        for i in 0..n {
            batch[i as usize] = self.rx_ring.desc(start.wrapping_add(i));
        }
        self.rx_ring.cons_release(n);

        n as usize
    }

    /// Get a packet slice for a received descriptor.
    ///
    /// # Safety
    ///
    /// The descriptor must have been received from [`recv`] and not yet
    /// recycled. The returned slice is only valid until the frame is
    /// returned to the fill ring via [`recycle`].
    pub unsafe fn pkt<'a>(&'a self, desc: &XdpDesc) -> &'a [u8] {
        self.umem.pkt(desc.addr, desc.len)
    }

    /// Recycle processed frames back to the fill ring.
    ///
    /// This returns the frames from the given descriptors to the UMEM
    /// free pool and then pushes as many free frames as possible into
    /// the fill ring so the kernel can use them for new RX packets.
    pub fn recycle(&mut self, descs: &[XdpDesc]) {
        // Return frames to the free pool.
        for desc in descs {
            self.umem.free_frame(desc.addr);
        }
        // Refill the fill ring from the free pool.
        self.refill();
    }

    /// Push free frames from the UMEM pool into the fill ring.
    ///
    /// Called automatically by `recycle`. Can also be called directly
    /// if frames are returned to the UMEM pool via other means.
    pub fn refill(&mut self) {
        let free = self.umem.free_count();
        if free == 0 {
            return;
        }

        let space = self.fill_ring.prod_free() as usize;
        let count = free.min(space);
        if count == 0 {
            return;
        }

        let start = self.fill_ring.cached_prod;
        for i in 0..count {
            let addr = self.umem.alloc_frame().unwrap();
            self.fill_ring.set_addr(start.wrapping_add(i as u32), addr);
        }
        self.fill_ring.prod_submit(count as u32);
    }

    /// Wait for RX activity using `poll(2)`.
    ///
    /// Returns `true` if packets are available, `false` on timeout.
    /// Pass `timeout_ms = -1` to block indefinitely.
    pub fn poll(&self, timeout_ms: i32) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a valid pollfd, nfds=1.
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret > 0)
        }
    }

    /// Check if the kernel needs a wakeup to process the fill ring.
    ///
    /// Only meaningful when bound with `XDP_USE_NEED_WAKEUP`. If this
    /// returns `true`, call [`wakeup`] after submitting fill ring entries.
    pub fn fill_needs_wakeup(&self) -> bool {
        self.fill_ring.needs_wakeup()
    }

    /// Wake up the kernel to process the fill ring.
    ///
    /// Uses `sendto(2)` with `MSG_DONTWAIT` as a lightweight wakeup signal.
    pub fn wakeup(&self) -> io::Result<()> {
        // SAFETY: sendto with null buffer and zero length is a no-op data-wise;
        // it just triggers the kernel to check for pending fill ring entries.
        let ret = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null(),
                0,
            )
        };
        if ret < 0 {
            let e = io::Error::last_os_error();
            // EAGAIN and ENOBUFS are expected (kernel busy), not errors.
            match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::ENOBUFS) => Ok(()),
                _ => Err(e),
            }
        } else {
            Ok(())
        }
    }

    /// Drain the completion ring, returning completed TX frames to the free pool.
    ///
    /// Not needed for RX-only operation, but useful when TX is active.
    pub fn drain_completion(&mut self) {
        let available = self.comp_ring.cons_available();
        if available == 0 {
            return;
        }

        let start = self.comp_ring.cached_cons;
        for i in 0..available {
            let addr = self.comp_ring.addr(start.wrapping_add(i));
            self.umem.free_frame(addr);
        }
        self.comp_ring.cons_release(available);
    }
}
