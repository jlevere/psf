//! Pure-Rust reader for Microsoft **PSTREAM** Patch Storage Files -- the
//! "express download" payload container used by Windows Update (LCU `.psf`,
//! FoD `.psf`, MSU PSTREAM).
//!
//! A PSTREAM file is a small header followed by a concatenation of payload
//! streams -- each typically a `PA30`/`PA31` (MSDelta) forward differential.
//! The container is **not self-indexing**: the map from a target file to its
//! `(offset, length)` stream lives in the paired Component Index manifest
//! (`express.psf.cix.xml`, carried in the update's `.wim`). This crate parses
//! the container and yields a stream's bytes by range; resolving names ->
//! ranges is the CIX manifest's job, one layer up.
//!
//! Sans-IO and zero-copy: `&[u8]` in, byte-slices out. Feed an extracted
//! stream straight to `msdelta` to reconstruct the target file.
//!
//! For containers too large to hold in memory, enable the `io` feature and
//! use [`reader::PsfReader`], a `Read + Seek` adapter that pulls streams by
//! range on demand. The core stays sans-IO; the adapter is opt-in.
#![forbid(unsafe_code)]

pub mod cix;
#[cfg(feature = "io")]
pub mod reader;

use thiserror::Error;

/// PSTREAM file magic (`"PSTREAM\0"`).
pub const MAGIC: &[u8; 8] = b"PSTREAM\0";

/// MSDelta blob magics a PSTREAM stream typically begins with.
pub const DELTA_MAGICS: [&[u8; 4]; 3] = [b"PA30", b"PA31", b"PA19"];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("not a PSTREAM file (bad magic)")]
    BadMagic,
    #[error("truncated PSF: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },
    #[error("stream range {offset}+{length} out of bounds (file is {size} bytes)")]
    OutOfBounds { offset: u64, length: u64, size: u64 },
    #[error("CIX parse error: {0}")]
    Cix(String),
}

pub type Result<T> = core::result::Result<T, Error>;

/// A stream located within a PSF by byte range (from the paired CIX manifest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsfStream {
    pub offset: u64,
    pub length: u64,
}

/// A parsed PSTREAM Patch Storage File (borrowed, zero-copy).
#[derive(Debug, Clone, Copy)]
pub struct Psf<'a> {
    data: &'a [u8],
    version: (u16, u16),
}

impl<'a> Psf<'a> {
    /// Parse and validate the PSTREAM header.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(Error::Truncated {
                need: 12,
                have: data.len(),
            });
        }
        if &data[..8] != MAGIC {
            return Err(Error::BadMagic);
        }
        let version = (
            u16::from_le_bytes([data[8], data[9]]),
            u16::from_le_bytes([data[10], data[11]]),
        );
        Ok(Self { data, version })
    }

    /// The container format version (`(2, 2)` for current files).
    pub fn version(&self) -> (u16, u16) {
        self.version
    }

    /// Total size of the file.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The raw bytes of a stream at the given range -- e.g. a `PA30` delta to
    /// hand to `msdelta`. The range comes from the paired CIX manifest.
    pub fn stream(&self, s: PsfStream) -> Result<&'a [u8]> {
        let off = s.offset as usize;
        let end = off
            .checked_add(s.length as usize)
            .filter(|&e| e <= self.data.len())
            .ok_or(Error::OutOfBounds {
                offset: s.offset,
                length: s.length,
                size: self.data.len() as u64,
            })?;
        Ok(&self.data[off..end])
    }

    /// Heuristically locate delta blobs by their MSDelta magic. Best-effort:
    /// authoritative `(offset, length)` ranges come from the CIX manifest, and
    /// a magic can coincidentally appear inside payload bytes. Useful for
    /// inspecting a `.psf` when no manifest is available.
    pub fn find_delta_blobs(&self) -> Vec<u64> {
        let mut out = Vec::new();
        // Streams start at or after the header; skip the 8-byte magic.
        let end = self.data.len().saturating_sub(4);
        let mut i = 8;
        while i <= end {
            let w = &self.data[i..i + 4];
            if DELTA_MAGICS.iter().any(|m| w == &m[..]) {
                out.push(i as u64);
            }
            i += 1;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(MAGIC);
        v.extend_from_slice(&2u16.to_le_bytes()); // major
        v.extend_from_slice(&2u16.to_le_bytes()); // minor
        v.resize(128, 0); // header padding to first stream
        v.extend_from_slice(b"PA30"); // a (fake) delta blob at offset 128
        v.extend_from_slice(&[0xAA; 60]);
        v
    }

    #[test]
    fn parses_header_and_version() {
        let data = synthetic();
        let psf = Psf::parse(&data).unwrap();
        assert_eq!(psf.version(), (2, 2));
    }

    #[test]
    fn rejects_bad_magic_and_truncation() {
        assert_eq!(
            Psf::parse(b"NOTPSF\0\0\x02\x00\x02\x00").unwrap_err(),
            Error::BadMagic
        );
        assert!(matches!(
            Psf::parse(b"PSTRE").unwrap_err(),
            Error::Truncated { .. }
        ));
    }

    #[test]
    fn extracts_stream_by_range_and_bounds_checks() {
        let data = synthetic();
        let psf = Psf::parse(&data).unwrap();
        let blob = psf
            .stream(PsfStream {
                offset: 128,
                length: 64,
            })
            .unwrap();
        assert_eq!(&blob[..4], b"PA30");
        assert_eq!(blob.len(), 64);
        assert!(matches!(
            psf.stream(PsfStream {
                offset: 128,
                length: 1 << 20
            }),
            Err(Error::OutOfBounds { .. })
        ));
    }

    #[test]
    fn finds_delta_blob() {
        let data = synthetic();
        let psf = Psf::parse(&data).unwrap();
        assert_eq!(psf.find_delta_blobs(), vec![128]);
    }

    #[test]
    fn stream_handles_boundary_and_overflow_ranges() {
        let data = synthetic();
        let psf = Psf::parse(&data).unwrap();
        let len = psf.len() as u64;
        // A zero-length read at EOF is valid and empty.
        assert_eq!(
            psf.stream(PsfStream {
                offset: len,
                length: 0
            })
            .unwrap(),
            b""
        );
        // One byte past EOF is rejected, not a panic.
        assert!(psf
            .stream(PsfStream {
                offset: len,
                length: 1
            })
            .is_err());
        // offset + length overflowing u64 is rejected, not a panic.
        assert!(psf
            .stream(PsfStream {
                offset: u64::MAX,
                length: 1
            })
            .is_err());
    }

    // Real fixture: `UUP_PSF_FIXTURE=/path/to/x.psf cargo test -p psf -- --nocapture`.
    #[test]
    fn real_psf_fixture() {
        let Ok(path) = std::env::var("UUP_PSF_FIXTURE") else {
            eprintln!("skip: set UUP_PSF_FIXTURE to a real .psf");
            return;
        };
        let data = std::fs::read(path).unwrap();
        let psf = Psf::parse(&data).unwrap();
        let blobs = psf.find_delta_blobs();
        eprintln!(
            "version={:?} size={} delta-blobs~={}",
            psf.version(),
            psf.len(),
            blobs.len()
        );
        assert_eq!(psf.version(), (2, 2));
        assert!(!blobs.is_empty());
        // First stream begins right after the 128-byte header.
        assert_eq!(blobs[0], 128);
        assert_eq!(
            &psf.stream(PsfStream {
                offset: blobs[0],
                length: 4
            })
            .unwrap(),
            b"PA30"
        );
    }
}
