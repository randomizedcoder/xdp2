//! Minimal PCAP file reader (no libpcap dependency).
//!
//! Reads the standard pcap format (magic 0xa1b2c3d4) and loads all packets
//! into memory. This mirrors the C `pcap_loader.h` approach of pre-loading
//! packets for benchmark timing.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// PCAP global header magic number (native byte order).
const PCAP_MAGIC: u32 = 0xa1b2c3d4;
/// PCAP global header magic number (swapped byte order).
const PCAP_MAGIC_SWAPPED: u32 = 0xd4c3b2a1;

/// A stored packet loaded from a PCAP file.
pub struct StoredPacket {
    pub data: Vec<u8>,
}

/// Load all packets from a PCAP file into memory.
pub fn load_pcap(path: &Path) -> Result<Vec<StoredPacket>, io::Error> {
    let buf = fs::read(path)?;
    if buf.len() < 24 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "PCAP too short"));
    }

    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let swapped = match magic {
        PCAP_MAGIC => false,
        PCAP_MAGIC_SWAPPED => true,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad PCAP magic: 0x{:08x}", magic),
            ))
        }
    };

    let read_u32 = |offset: usize| -> u32 {
        let b: [u8; 4] = buf[offset..offset + 4].try_into().unwrap();
        if swapped {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    };

    let mut packets = Vec::new();
    let mut pos = 24; // skip global header

    while pos + 16 <= buf.len() {
        // Packet record header: ts_sec(4) ts_usec(4) caplen(4) origlen(4)
        let caplen = read_u32(pos + 8) as usize;
        pos += 16;

        if pos + caplen > buf.len() {
            break; // truncated packet
        }

        packets.push(StoredPacket {
            data: buf[pos..pos + caplen].to_vec(),
        });
        pos += caplen;
    }

    Ok(packets)
}

/// Write packets to a PCAP file (Ethernet linktype).
pub fn write_pcap(path: &Path, packets: &[StoredPacket]) -> Result<(), io::Error> {
    let mut f = fs::File::create(path)?;

    // Global header: magic, version 2.4, snaplen 65535, linktype 1 (Ethernet)
    f.write_all(&PCAP_MAGIC.to_le_bytes())?;
    f.write_all(&2u16.to_le_bytes())?; // version major
    f.write_all(&4u16.to_le_bytes())?; // version minor
    f.write_all(&0i32.to_le_bytes())?; // thiszone
    f.write_all(&0u32.to_le_bytes())?; // sigfigs
    f.write_all(&65535u32.to_le_bytes())?; // snaplen
    f.write_all(&1u32.to_le_bytes())?; // linktype: LINKTYPE_ETHERNET

    for (i, pkt) in packets.iter().enumerate() {
        let caplen = pkt.data.len() as u32;
        // Packet header: ts_sec, ts_usec, caplen, origlen
        f.write_all(&(i as u32).to_le_bytes())?; // ts_sec (use index as fake timestamp)
        f.write_all(&0u32.to_le_bytes())?; // ts_usec
        f.write_all(&caplen.to_le_bytes())?;
        f.write_all(&caplen.to_le_bytes())?;
        f.write_all(&pkt.data)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_short_file() {
        let path = Path::new("/dev/null");
        let result = load_pcap(path);
        assert!(result.is_err());
    }
}
