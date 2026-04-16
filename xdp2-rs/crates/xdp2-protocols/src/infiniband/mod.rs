//! InfiniBand protocol family.
//!
//! ## C/C++ Cross-Reference
//! Source directory: `src/include/xdp2/proto_defs/infiniband/`

pub mod ib_lrh;
pub mod ib_mad;
pub mod ib_rdeth;
pub mod ib_transport;

pub use ib_lrh::{IbLrhHeader, IbLrhOps};
pub use ib_mad::{IbMadHeader, IbMadOps};
pub use ib_rdeth::{IbRdethHeader, IbRdethOps};
pub use ib_transport::{
    IbAethHeader, IbAethOps, IbAtomicethHeader, IbAtomicethOps, IbBthHeader, IbBthOps,
    IbDethHeader, IbDethOps, IbGrhHeader, IbGrhOps, IbImmdtHeader, IbImmdtOps, IbRethHeader,
    IbRethOps,
};
