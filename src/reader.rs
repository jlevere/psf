//! A `Read + Seek` adapter for PSTREAM containers too large to hold in
//! memory (express-download payloads run to hundreds of MB or more).
//!
//! [`Psf`](crate::Psf) borrows the whole file and hands back zero-copy
//! slices. [`PsfReader`] instead validates the header from a stream, learns
//! the total length once, and pulls each [`PsfStream`] range on demand with a
//! `seek` + `read_exact` -- nothing beyond the requested stream is resident.
//!
//! This module performs IO, so it is gated behind the `io` feature; the core
//! parser stays sans-IO.

use std::io::{self, Read, Seek, SeekFrom};

use crate::{Error, PsfStream, MAGIC};

/// An error from the IO-backed reader: either a malformed container
/// ([`Error`]) or an underlying IO failure.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The container is not a valid PSTREAM file or a range is out of bounds.
    #[error(transparent)]
    Psf(#[from] Error),
    /// The underlying `Read`/`Seek` source failed.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = core::result::Result<T, ReadError>;

/// A PSTREAM container read incrementally from a `Read + Seek` source.
///
/// ```no_run
/// use std::fs::File;
/// use psf::{PsfStream, reader::PsfReader};
///
/// let mut psf = PsfReader::new(File::open("express.psf")?)?;
/// let blob = psf.stream(PsfStream { offset: 128, length: 4595 })?;
/// // -> msdelta::pa30::apply(base, &blob)
/// # Ok::<(), psf::reader::ReadError>(())
/// ```
#[derive(Debug, Clone)]
pub struct PsfReader<R> {
    inner: R,
    version: (u16, u16),
    len: u64,
}

impl<R: Read + Seek> PsfReader<R> {
    /// Read and validate the PSTREAM header from the current position, then
    /// determine the total length by seeking to the end. Leaves the cursor at
    /// end-of-file; [`stream`](Self::stream) seeks explicitly per call.
    pub fn new(mut inner: R) -> Result<Self> {
        let mut header = [0u8; 12];
        let read = fill(&mut inner, &mut header)?;
        if read < 12 {
            return Err(Error::Truncated {
                need: 12,
                have: read,
            }
            .into());
        }
        if &header[..8] != MAGIC {
            return Err(Error::BadMagic.into());
        }
        let version = (
            u16::from_le_bytes([header[8], header[9]]),
            u16::from_le_bytes([header[10], header[11]]),
        );
        let len = inner.seek(SeekFrom::End(0))?;
        Ok(Self {
            inner,
            version,
            len,
        })
    }

    /// The container format version (`(2, 2)` for current files).
    pub fn version(&self) -> (u16, u16) {
        self.version
    }

    /// Total size of the container in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Read a stream's bytes by range into a freshly allocated `Vec`.
    ///
    /// The range comes from the paired CIX manifest. To reuse a buffer across
    /// many streams, prefer [`read_stream_into`](Self::read_stream_into).
    pub fn stream(&mut self, s: PsfStream) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.read_stream_into(s, &mut buf)?;
        Ok(buf)
    }

    /// Read a stream's bytes by range into `buf`, clearing it first and
    /// reusing its allocation. Bounds-checks the range against the container
    /// length before touching the source.
    pub fn read_stream_into(&mut self, s: PsfStream, buf: &mut Vec<u8>) -> Result<()> {
        s.offset
            .checked_add(s.length)
            .filter(|&end| end <= self.len)
            .ok_or(Error::OutOfBounds {
                offset: s.offset,
                length: s.length,
                size: self.len as usize,
            })?;
        self.inner.seek(SeekFrom::Start(s.offset))?;
        buf.clear();
        buf.resize(s.length as usize, 0);
        self.inner.read_exact(buf)?;
        Ok(())
    }

    /// Consume the reader and return the underlying source.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Read up to `buf.len()` bytes, returning how many were filled. Unlike
/// `read_exact`, a short read is reported (not an error) so the caller can
/// distinguish truncation from an IO fault.
fn fill<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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
    fn reads_header_and_length() {
        let data = synthetic();
        let len = data.len() as u64;
        let psf = PsfReader::new(Cursor::new(data)).unwrap();
        assert_eq!(psf.version(), (2, 2));
        assert_eq!(psf.len(), len);
        assert!(!psf.is_empty());
    }

    #[test]
    fn rejects_bad_magic_and_truncation() {
        let bad = PsfReader::new(Cursor::new(b"NOTPSF\0\0\x02\x00\x02\x00".to_vec()));
        assert!(matches!(bad.unwrap_err(), ReadError::Psf(Error::BadMagic)));
        let short = PsfReader::new(Cursor::new(b"PSTRE".to_vec()));
        assert!(matches!(
            short.unwrap_err(),
            ReadError::Psf(Error::Truncated { need: 12, have: 5 })
        ));
    }

    #[test]
    fn reads_stream_by_range_and_bounds_checks() {
        let mut psf = PsfReader::new(Cursor::new(synthetic())).unwrap();
        let blob = psf
            .stream(PsfStream {
                offset: 128,
                length: 64,
            })
            .unwrap();
        assert_eq!(&blob[..4], b"PA30");
        assert_eq!(blob.len(), 64);

        let oob = psf.stream(PsfStream {
            offset: 128,
            length: 1 << 20,
        });
        assert!(matches!(
            oob.unwrap_err(),
            ReadError::Psf(Error::OutOfBounds { .. })
        ));
    }

    #[test]
    fn read_stream_into_reuses_buffer() {
        let mut psf = PsfReader::new(Cursor::new(synthetic())).unwrap();
        let mut buf = Vec::with_capacity(256);
        psf.read_stream_into(
            PsfStream {
                offset: 128,
                length: 4,
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf, b"PA30");
        // A shorter follow-up read clears the prior contents.
        psf.read_stream_into(
            PsfStream {
                offset: 8,
                length: 2,
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf, 2u16.to_le_bytes());
    }

    // Real fixture: `UUP_PSF_FIXTURE=/path/to/x.psf cargo test -p psf --features io -- --nocapture`.
    #[test]
    fn real_psf_fixture() {
        let Ok(path) = std::env::var("UUP_PSF_FIXTURE") else {
            eprintln!("skip: set UUP_PSF_FIXTURE to a real .psf");
            return;
        };
        let mut psf = PsfReader::new(std::fs::File::open(path).unwrap()).unwrap();
        eprintln!("version={:?} size={}", psf.version(), psf.len());
        assert_eq!(psf.version(), (2, 2));
        // First stream begins right after the 128-byte header.
        let head = psf
            .stream(PsfStream {
                offset: 128,
                length: 4,
            })
            .unwrap();
        assert_eq!(&head, b"PA30");
    }
}
