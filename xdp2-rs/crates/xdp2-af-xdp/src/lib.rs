//! AF_XDP socket abstraction for zero-copy packet I/O.
//!
//! This crate provides a safe Rust interface to Linux AF_XDP sockets,
//! enabling zero-copy packet reception from a NIC via shared memory (UMEM).
//!
//! # Architecture
//!
//! ```text
//!   NIC → XDP program → XDP_REDIRECT → XSKMAP → UMEM → Rust parser
//! ```
//!
//! The kernel writes received packets directly into UMEM frames. Userspace
//! reads them via the RX ring (descriptors pointing into UMEM) with zero
//! copies. Processed frames are returned via the fill ring for reuse.
//!
//! # Example
//!
//! ```no_run
//! use xdp2_af_xdp::{XskSocket, Config, XdpDesc};
//!
//! let config = Config::default();
//! let mut xsk = XskSocket::bind("eth0", 0, config).unwrap();
//!
//! let mut batch = vec![XdpDesc::default(); 64];
//! loop {
//!     let n = xsk.recv(&mut batch);
//!     for desc in &batch[..n] {
//!         let pkt = unsafe { xsk.pkt(desc) };
//!         // Parse packet...
//!     }
//!     xsk.recycle(&batch[..n]);
//! }
//! ```

#[cfg(not(target_os = "linux"))]
compile_error!("xdp2-af-xdp requires Linux (AF_XDP is a Linux-only API)");

pub mod sys;
mod umem;
mod socket;
mod rx;

pub use sys::XdpDesc;
pub use umem::{Umem, UmemConfig};
pub use socket::XskSocket;

use umem::UmemConfig as UmemCfg;

/// Socket configuration.
pub struct SocketConfig {
    /// RX ring size (must be power of 2).
    pub rx_ring_size: u32,
    /// Fill ring size (must be power of 2).
    pub fill_ring_size: u32,
    /// Completion ring size (must be power of 2).
    pub comp_ring_size: u32,
    /// Bind flags: `XDP_COPY`, `XDP_ZEROCOPY`, `XDP_USE_NEED_WAKEUP`.
    pub bind_flags: u16,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            rx_ring_size: 2048,
            fill_ring_size: 2048,
            comp_ring_size: 2048,
            bind_flags: 0,
        }
    }
}

/// Combined UMEM + socket configuration.
pub struct Config {
    pub umem: UmemCfg,
    pub socket: SocketConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            umem: UmemCfg::default(),
            socket: SocketConfig::default(),
        }
    }
}

/// Errors from AF_XDP operations.
#[derive(Debug)]
pub enum Error {
    /// System call failed.
    Io(std::io::Error),
    /// Network interface not found.
    InterfaceNotFound(String),
    /// Ring size is not a power of 2.
    InvalidRingSize(u32),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "AF_XDP I/O error: {e}"),
            Error::InterfaceNotFound(name) => write!(f, "interface not found: {name}"),
            Error::InvalidRingSize(n) => write!(f, "ring size {n} is not a power of 2"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}
