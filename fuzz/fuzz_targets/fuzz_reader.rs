#![no_main]

use libfuzzer_sys::fuzz_target;
use psf::{reader::PsfReader, Psf, PsfStream};
use std::io::Cursor;

// Differential oracle. The Read+Seek adapter and the in-memory parser are two
// implementations of one contract, so they must agree on EVERY decision for
// the same bytes: header validity, version, length, and each range read (same
// Ok/Err, same bytes). Any divergence -- a bounds off-by-one, a usize/u64 cast
// gone wrong, a header-length mismatch -- fails here. Reuses fuzz/psf.dict.
fuzz_target!(|data: &[u8]| {
    let mem = Psf::parse(data);
    let rdr = PsfReader::new(Cursor::new(data));

    assert_eq!(
        mem.is_ok(),
        rdr.is_ok(),
        "header validity disagreement (mem={} rdr={})",
        mem.is_ok(),
        rdr.is_ok(),
    );
    let (Ok(mem), Ok(mut rdr)) = (mem, rdr) else {
        return;
    };

    assert_eq!(mem.version(), rdr.version(), "version disagreement");
    assert_eq!(mem.len() as u64, rdr.len(), "length disagreement");

    let len = rdr.len();
    let edges = [
        (0u64, 0u64),
        (0, len),
        (len, 0),
        (len, 1),
        (len.saturating_sub(1), 1),
        (len.saturating_sub(1), 2),
        (0, len + 1),
        (8, 4),
        (u64::MAX, 0),
        (u64::MAX - 4, 8),
    ];
    for (offset, length) in edges {
        let s = PsfStream { offset, length };
        match (mem.stream(s), rdr.stream(s)) {
            (Ok(a), Ok(b)) => assert_eq!(a, &b[..], "byte disagreement at {offset}+{length}"),
            (Err(_), Err(_)) => {}
            (a, b) => panic!(
                "ok/err disagreement at {offset}+{length}: mem.ok={} rdr.ok={}",
                a.is_ok(),
                b.is_ok(),
            ),
        }
    }
});
