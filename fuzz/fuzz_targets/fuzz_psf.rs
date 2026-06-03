#![no_main]

use libfuzzer_sys::fuzz_target;
use psf::{Psf, PsfStream};

// The PSTREAM header parser, the delta-blob scanner, and range extraction must
// never panic on arbitrary input, and every range they hand back must stay in
// bounds. Pair with fuzz/psf.dict so the mutator gets past the magic gate:
//   cargo fuzz run fuzz_psf -- -dict=fuzz/psf.dict
fuzz_target!(|data: &[u8]| {
    let Ok(psf) = Psf::parse(data) else { return };
    let len = psf.len() as u64;

    // Each located blob offset must yield a bounds-checked slice.
    for off in psf.find_delta_blobs() {
        if let Ok(blob) = psf.stream(PsfStream { offset: off, length: 4 }) {
            assert!(blob.len() == 4);
        }
    }

    // Reading the whole container must succeed and match its length; one byte
    // past the end must be rejected rather than panic.
    let whole = psf.stream(PsfStream { offset: 0, length: len }).unwrap();
    assert_eq!(whole.len() as u64, len);
    assert!(psf
        .stream(PsfStream {
            offset: len,
            length: 1,
        })
        .is_err());
});
