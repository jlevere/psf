# psf

Pure-Rust reader for Microsoft **PSTREAM** Patch Storage Files -- the "express
download" payload container used by Windows Update (LCU `.psf`, FoD `.psf`, MSU
PSTREAM) -- and their paired **Container Index** (`*.psf.cix.xml`).

A PSTREAM file is a small header followed by concatenated payload streams (each
typically a `PA30`/`PA31` MSDelta differential). The container is not
self-indexing: the map from a target file to its `(offset, length)` stream
lives in the CIX manifest. This crate parses both and yields a stream's bytes
by range; feed those to [`msdelta`](https://github.com/jlevere/msdelta) to
reconstruct the target file.

Sans-IO and zero-copy: `&[u8]` in, byte-slices out.

```rust
use psf::{Psf, cix::ContainerIndex};

let cix = ContainerIndex::parse(cix_xml)?;
let psf = Psf::parse(psf_bytes)?;
for file in cix.files() {
    if let Some(stream) = file.psf_stream() {
        let blob = psf.stream(stream)?; // PA30 delta or RAW bytes
        // -> msdelta::pa30::apply(base, blob)
    }
}
# Ok::<(), psf::Error>(())
```

Consumed by [`uup`](https://github.com/jlevere/uup) and
[`msu`](https://github.com/jlevere/msu). Licensed under MIT OR Apache-2.0.
