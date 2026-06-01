//! Extractor for Microsoft **Patch Storage Files** (PSF), the "express
//! download" payload container used by Windows Update.
//!
//! A UUP cumulative update ships as a `.wim` + `.psf` pair: the `.wim` holds
//! the file index and metadata, while the `.psf` is a flat concatenation of
//! per-file payload streams -- each stream a forward differential to be
//! applied with `msdelta`, or a whole file. This crate parses the container
//! and yields the bytes of an individual stream by `(offset, length)`; the
//! index that maps a target file to its stream lives in the sibling `.wim`
//! (read with `wim-rs`) and is resolved one layer up, in the `uup` crate.
//!
//! See `PLAN.md` milestone M4 and `notes/uup-fileset-anatomy.md`.
#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid PSF: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A payload stream located within a PSF container by byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsfStream {
    pub offset: u64,
    pub length: u64,
}
