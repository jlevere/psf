#![no_main]

use libfuzzer_sys::fuzz_target;
use psf::{Psf, PsfStream, DELTA_MAGICS};

// Range oracle for the in-memory parser. Properties that MUST hold, or this
// fails (not just "didn't panic"):
//   - find_delta_blobs only returns post-header, in-bounds offsets that
//     genuinely carry a delta magic -- it must not invent or misplace offsets.
//   - stream(offset, length) is Ok iff offset+length neither overflows nor
//     exceeds len, and on Ok yields exactly data[offset..offset+length].
// Pair with fuzz/psf.dict to get past the magic gate.
fuzz_target!(|data: &[u8]| {
    let Ok(psf) = Psf::parse(data) else {
        return;
    };
    let len = psf.len() as u64;
    assert_eq!(psf.len(), data.len(), "len() disagrees with input");

    for off in psf.find_delta_blobs() {
        assert!(off >= 8, "scanner returned offset {off} inside the header");
        let blob = psf
            .stream(PsfStream {
                offset: off,
                length: 4,
            })
            .expect("scanner returned an out-of-bounds offset");
        assert!(
            DELTA_MAGICS.iter().any(|m| blob == &m[..]),
            "scanner returned offset {off} with no delta magic there",
        );
    }

    // Edge ranges, including overflow and one-past-end on both sides.
    let edges = [
        (0u64, 0u64),
        (0, len),
        (len, 0),
        (len, 1),
        (len.saturating_sub(1), 1),
        (len.saturating_sub(1), 2),
        (0, len + 1),
        (1, len),
        (u64::MAX, 0),
        (u64::MAX - 4, 8),
    ];
    for (offset, length) in edges {
        let in_bounds = offset.checked_add(length).is_some_and(|end| end <= len);
        match psf.stream(PsfStream { offset, length }) {
            Ok(b) => {
                assert!(in_bounds, "accepted out-of-bounds range {offset}+{length}");
                assert_eq!(b.len() as u64, length, "wrong slice length");
                let o = offset as usize;
                assert_eq!(b, &data[o..o + length as usize], "slice content mismatch");
            }
            Err(_) => assert!(!in_bounds, "rejected in-bounds range {offset}+{length}"),
        }
    }
});
