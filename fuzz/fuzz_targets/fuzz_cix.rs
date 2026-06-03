#![no_main]

use libfuzzer_sys::fuzz_target;
use psf::cix::ContainerIndex;

// The CIX manifest parser runs yaserde / xml-rs over attacker-controlled XML
// (the .psf.cix.xml ships inside the update). It must never panic or hang on
// malformed input -- only return Err. Seed the corpus with a real manifest and
// pair with fuzz/cix.dict for the element and attribute names:
//   cargo fuzz run fuzz_cix -- -dict=fuzz/cix.dict
fuzz_target!(|data: &[u8]| {
    // The parser takes &str; only valid UTF-8 reaches it.
    let Ok(xml) = std::str::from_utf8(data) else {
        return;
    };
    let _ = ContainerIndex::parse(xml);
});
