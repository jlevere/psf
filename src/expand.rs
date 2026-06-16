//! Reconstruct target files from a PSF + its CIX -- the shared `dpx.dll`
//! `CContainer` pipeline (the single copy; `msu`, `cbs-apply`, and `uup` call
//! this instead of each rolling their own).
//!
//! Forward (`dpx!PsfExpandDelta` -> `ApplyDeltaB`): a `RAW` source is the file
//! stored verbatim; a `PA30`/`PA31` source is an MSDelta applied to a basis (the
//! null base `&[]` for a baseless container). The result can be verified against
//! the CIX target SHA256/length.
//!
//! Backward (`dpx!ApplyDeltaGetReverseB`): derive the reverse delta and apply it
//! to recover the basis -- a round-trip check.
//!
//! Enabled by the `expand` feature (pulls in `msdelta` + `sha2`).

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::cix::{File, Hash};
use crate::Psf;

/// Errors reconstructing a target file.
#[derive(Debug, Error)]
pub enum ExpandError {
    /// The CIX `File` has no `<Source>` (nothing to reconstruct from).
    #[error("{name}: no source in CIX")]
    NoSource { name: String },
    /// The PSF stream range was bad (truncated / out of bounds).
    #[error(transparent)]
    Psf(#[from] crate::Error),
    /// `msdelta` failed to apply the delta.
    #[error("{name}: msdelta apply: {msg}")]
    Apply { name: String, msg: String },
    /// A non-RAW, non-delta source (e.g. a WIM-fragment LZX/XPRESS/LZMS stream,
    /// `dpx!PsfExpandWimFragment`) we don't decode -- fail loud rather than
    /// mis-copy the compressed bytes as verbatim.
    #[error("{name}: unsupported source type {kind:?} (only RAW and PA30/PA31)")]
    UnsupportedSource { name: String, kind: String },
    /// Reconstructed bytes did not match the CIX target hash/length.
    #[error("{name}: reconstructed bytes do not match CIX target hash/length")]
    TargetMismatch { name: String },
}

type Result<T> = core::result::Result<T, ExpandError>;

fn sha256_upper(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// Whether `bytes` match a CIX `<Hash>` (only SHA256 is checked; an absent or
/// unknown-algorithm hash is treated as "don't claim a mismatch").
fn hash_matches(hash: &Option<Hash>, bytes: &[u8]) -> bool {
    match hash {
        Some(h) if h.alg.eq_ignore_ascii_case("SHA256") => {
            sha256_upper(bytes).eq_ignore_ascii_case(&h.value)
        }
        _ => true,
    }
}

/// Reconstruct a file's target bytes from the PSF (forward). `basis` is the
/// source file for non-baseless deltas; pass `&[]` for a baseless container or a
/// `RAW` source.
pub fn reconstruct(psf: &Psf, file: &File, basis: &[u8]) -> Result<Vec<u8>> {
    let source = file.source().ok_or_else(|| ExpandError::NoSource {
        name: file.name.clone(),
    })?;
    let stream = psf.stream(source.stream())?;
    if source.is_delta() {
        msdelta::pa30::apply(basis, stream).map_err(|e| ExpandError::Apply {
            name: file.name.clone(),
            msg: e.to_string(),
        })
    } else if source.kind.eq_ignore_ascii_case("RAW") {
        // RAW: the source range is the file, stored verbatim.
        Ok(stream.to_vec())
    } else {
        Err(ExpandError::UnsupportedSource {
            name: file.name.clone(),
            kind: source.kind.clone(),
        })
    }
}

/// `true` if `bytes` match the CIX target length and SHA256.
pub fn verify_target(file: &File, bytes: &[u8]) -> bool {
    file.length == bytes.len() as u64 && hash_matches(&file.hash, bytes)
}

/// Reconstruct and verify against the CIX target hash + length.
pub fn reconstruct_verified(psf: &Psf, file: &File, basis: &[u8]) -> Result<Vec<u8>> {
    let bytes = reconstruct(psf, file, basis)?;
    if !verify_target(file, &bytes) {
        return Err(ExpandError::TargetMismatch {
            name: file.name.clone(),
        });
    }
    Ok(bytes)
}

/// Verify the extracted source stream matches the CIX source SHA256 -- i.e. the
/// `.psf` byte range was extracted exactly. Pure container check (no msdelta).
pub fn verify_source(psf: &Psf, file: &File) -> Result<bool> {
    let source = file.source().ok_or_else(|| ExpandError::NoSource {
        name: file.name.clone(),
    })?;
    let stream = psf.stream(source.stream())?;
    Ok(hash_matches(&source.hash, stream))
}

/// Backward round-trip for a delta file: forward-apply to the target, derive the
/// reverse delta, then apply it to recover the basis. Returns whether the
/// round-trip reproduced the basis exactly. A `RAW` source has no delta to
/// reverse and returns `true`.
pub fn reverse_roundtrips(psf: &Psf, file: &File, basis: &[u8]) -> Result<bool> {
    let source = file.source().ok_or_else(|| ExpandError::NoSource {
        name: file.name.clone(),
    })?;
    if !source.is_delta() {
        return Ok(true);
    }
    let delta = psf.stream(source.stream())?;
    let name = || file.name.clone();
    let (target, reverse) =
        msdelta::pa30::apply_get_reverse(basis, delta).map_err(|e| ExpandError::Apply {
            name: name(),
            msg: e.to_string(),
        })?;
    let recovered = msdelta::pa30::apply(&target, &reverse).map_err(|e| ExpandError::Apply {
        name: name(),
        msg: e.to_string(),
    })?;
    Ok(recovered == basis)
}
