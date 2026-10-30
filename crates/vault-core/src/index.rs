//! Plaintext encoding of the vault index (encrypted before storage).
//!
//! ```text
//! u32 count
//! per entry:
//!   u16 path_len, path (UTF-8)
//!   u64 size, u64 compressed_size, i64 modified (unix seconds)
//!   u64 offset, u64 length, [19] stream nonce prefix, u32 chunk_size
//! ```
//! All integers little-endian. Decoding enforces every bound so a malformed
//! index can only produce an error, never a panic or a huge allocation.

use std::collections::HashSet;

use zeroize::Zeroizing;

use crate::pathsafe;
use crate::vault::{Entry, CHUNK_SIZE, STREAM_NONCE_LEN, TAG_LEN};
use crate::{Error, Result};

pub const MAX_ENTRIES: u32 = 1_000_000;

pub fn encode(entries: &[Entry]) -> Zeroizing<Vec<u8>> {
    let mut out = Vec::with_capacity(4 + entries.len() * 96);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        let p = e.path.as_bytes();
        out.extend_from_slice(&(p.len() as u16).to_le_bytes());
        out.extend_from_slice(p);
        out.extend_from_slice(&e.size.to_le_bytes());
        out.extend_from_slice(&e.compressed_size.to_le_bytes());
        out.extend_from_slice(&e.modified.to_le_bytes());
        out.extend_from_slice(&e.offset.to_le_bytes());
        out.extend_from_slice(&e.length.to_le_bytes());
        out.extend_from_slice(&e.nonce_prefix);
        out.extend_from_slice(&e.chunk_size.to_le_bytes());
    }
    Zeroizing::new(out)
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Tampered)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::Tampered)?;
        self.pos = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("2")))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4")))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8")))
    }
}

/// Expected ciphertext length of an entry stream.
pub fn stream_len(compressed_size: u64, chunk_size: u32) -> Option<u64> {
    let cs = chunk_size as u64;
    let chunks = if compressed_size == 0 {
        1
    } else {
        compressed_size.div_ceil(cs)
    };
    compressed_size.checked_add(chunks.checked_mul(TAG_LEN)?)
}

/// Decodes an index. `data_start..data_end` is the byte range of the vault
/// that entry streams must lie within.
pub fn decode(buf: &[u8], data_start: u64, data_end: u64) -> Result<Vec<Entry>> {
    let mut c = Cursor { buf, pos: 0 };
    let count = c.u32()?;
    if count > MAX_ENTRIES {
        return Err(Error::LimitExceeded("too many entries"));
    }
    let mut seen = HashSet::new();
    let mut entries = Vec::with_capacity(count.min(4096) as usize);
    for _ in 0..count {
        let plen = c.u16()? as usize;
        let path = std::str::from_utf8(c.take(plen)?)
            .map_err(|_| Error::Tampered)?
            .to_owned();
        pathsafe::validate(&path)?;
        if !seen.insert(pathsafe::fold(&path)) {
            return Err(Error::UnsafePath(format!("{path:?}: duplicate entry")));
        }
        let size = c.u64()?;
        let compressed_size = c.u64()?;
        let modified = c.u64()? as i64;
        let offset = c.u64()?;
        let length = c.u64()?;
        let mut nonce_prefix = [0u8; STREAM_NONCE_LEN];
        nonce_prefix.copy_from_slice(c.take(STREAM_NONCE_LEN)?);
        let chunk_size = c.u32()?;

        if chunk_size != CHUNK_SIZE {
            return Err(Error::Unsupported(format!("chunk size {chunk_size}")));
        }
        let end = offset.checked_add(length).ok_or(Error::Tampered)?;
        if offset < data_start
            || end > data_end
            || stream_len(compressed_size, chunk_size) != Some(length)
        {
            return Err(Error::Tampered);
        }
        entries.push(Entry {
            path,
            size,
            compressed_size,
            modified,
            offset,
            length,
            nonce_prefix,
            chunk_size,
        });
    }
    if c.pos != buf.len() {
        return Err(Error::Tampered);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_len_matches_chunking() {
        let cs = CHUNK_SIZE;
        let c = cs as u64;
        assert_eq!(stream_len(0, cs), Some(16));
        assert_eq!(stream_len(1, cs), Some(17));
        assert_eq!(stream_len(c, cs), Some(c + 16));
        assert_eq!(stream_len(c + 1, cs), Some(c + 1 + 32));
        assert_eq!(stream_len(2 * c, cs), Some(2 * c + 32));
    }

    #[test]
    fn garbage_never_panics() {
        let mut seed = 0x1234_5678_9abc_def0u64;
        for len in 0..512 {
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    seed as u8
                })
                .collect();
            let _ = decode(&buf, 116, 1 << 40);
        }
    }
}
