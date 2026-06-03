# psf

Pure-Rust reader for Microsoft PSTREAM Patch Storage Files (`*.psf`, the
"express download" payload) and their Container Index (`*.psf.cix.xml`).

This crate was extracted from the `uup` repo so that both `uup` (UUP fileset
acquisition) and `msu` (standalone-package parsing) can depend on it as equals.
It owns exactly two things: the PSTREAM container reader and the CIX manifest
model. Everything downstream (delta apply, WIM, container orchestration) lives
in the consuming crates.

## Scope

- `Psf` -- parse/validate the PSTREAM header, yield a stream's bytes by
  `(offset, length)` range, heuristically locate delta blobs.
- `cix::ContainerIndex` -- parse `express.psf.cix.xml`: per-file source
  (`RAW` range or `PA30`/`PA31`/`PA19` delta), target/source SHA256s, and the
  `DeltaBasisSearch` locations for non-baseless deltas.

## Conventions

- Sans-IO, zero-copy: `&[u8]`/`&str` in, byte-slices out. No filesystem, clock,
  or RNG in the core.
- XML is parsed with typed `yaserde` derive models -- never `format!` strings
  or hand-rolled parsers.
- Strong types everywhere; no stringly-typed blobs where a real type fits.
- No emojis in source, comments, or commit messages.
- Real `.psf`/CIX fixtures are git-ignored; fixture-backed tests skip when the
  file is absent (see `UUP_PSF_FIXTURE`).

## RE reference

Format semantics come from `dpx.dll` (`CContainer::FromXml` /
`ProvideContainerIndex` / `LinkCixTargets`). The decompile lives out of tree
(`~/projects/cbs-re/reference`, `~/projects/uup/reference/dpx`); do not paste
decompiler output into this repo.

## Dev environment

```sh
nix develop
cargo build
cargo nextest run
```

Both parse surfaces (the PSTREAM header/scanner and the CIX XML manifest) take
attacker-controlled input and are fuzzed with `cargo-fuzz`. The fuzz crate is a
standalone workspace under `fuzz/` (excluded from the root workspace); enter the
nightly shell with `nix develop .#fuzz`, seed with `./fuzz/seed_corpus.sh`, then
`cargo fuzz run <fuzz_cix|fuzz_psf|fuzz_reader> -- -dict=fuzz/<cix|psf>.dict`.
