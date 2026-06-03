#![no_main]

use libfuzzer_sys::fuzz_target;
use psf::cix::ContainerIndex;

// The CIX manifest parser runs yaserde / xml-rs over attacker-controlled XML
// (the .psf.cix.xml ships inside the update). It must never panic or hang. On
// success the accessors must be self-consistent -- a divergence between
// psf_stream() and source(), or is_delta() and the raw kind, is a bug. Seed
// the corpus with a real manifest and pair with fuzz/cix.dict.
fuzz_target!(|data: &[u8]| {
    // The parser takes &str; only valid UTF-8 reaches it.
    let Ok(xml) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(cix) = ContainerIndex::parse(xml) else {
        return;
    };

    assert_eq!(
        cix.is_baseless(),
        cix.name.contains("baseless"),
        "is_baseless disagrees with the container name",
    );

    for f in cix.files() {
        match (f.source(), f.psf_stream()) {
            (Some(src), Some(stream)) => {
                assert_eq!(stream, src.stream(), "psf_stream() != source().stream()");
                assert_eq!(
                    src.is_delta(),
                    src.kind.starts_with("PA"),
                    "is_delta() disagrees with kind {:?}",
                    src.kind,
                );
            }
            (None, None) => {}
            (s, p) => panic!(
                "source()/psf_stream() presence disagree for {:?}: src={} stream={}",
                f.name,
                s.is_some(),
                p.is_some(),
            ),
        }
    }
});
