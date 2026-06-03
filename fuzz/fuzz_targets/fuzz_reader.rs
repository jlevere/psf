#![no_main]

use libfuzzer_sys::fuzz_target;
use psf::{reader::PsfReader, PsfStream};
use std::io::Cursor;

// The Read+Seek adapter validates the header from the stream and pulls ranges
// with seek + read_exact. On arbitrary input it must error cleanly rather than
// panic, and its bounds check must agree with the in-memory path. Reuses
// fuzz/psf.dict:
//   cargo fuzz run fuzz_reader -- -dict=fuzz/psf.dict
fuzz_target!(|data: &[u8]| {
    let Ok(mut psf) = PsfReader::new(Cursor::new(data)) else {
        return;
    };
    let len = psf.len();

    // Reading the whole container must succeed and match its length.
    let whole = psf.stream(PsfStream { offset: 0, length: len }).unwrap();
    assert_eq!(whole.len() as u64, len);

    // A range starting at end-of-file must be rejected, not panic.
    assert!(psf
        .stream(PsfStream {
            offset: len,
            length: 16,
        })
        .is_err());
});
