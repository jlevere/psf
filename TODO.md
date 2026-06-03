# psf TODO — CIX/PSF model completeness

The current model parses the **baseless-LCU happy path** (validated end-to-end
against KB5089549 via `msu`). A dpx-decompile audit (`*::FromXml` in
`~/projects/msu/reference/ghidra/decompiled_dpx/`) shows the real CIX/PSF is a
superset. Items below are tied to the proving function. Add as real target
packages require them — the baseless OS-LCU path does not.

## Current model (baseline)
- `Psf`: `PSTREAM` magic + (major,minor) version; `stream(offset,len)`;
  `find_delta_blobs`. No embedded index, no encryption, no compression.
- CIX: `ContainerIndex{name,type,length,version,DeltaBasisSearch?,Files}`,
  `File{id,name,length,time,attr,Hash?,Delta?}`, `Delta{Source}`,
  `Source{type,offset,length,Hash?}`, `Hash{alg,value}`, `Location{id,path,flags}`.

## P0 — correctness for real PSFs
- [ ] **PSF embeds its own CIX.** Header is 0x30 bytes; CIX `offset = u32@0x28`,
      `len = u32@0x2c`; slice `[offset, offset+len)`. Min size 0x30 + bounds
      check. Prefer embedded over sidecar. (`GetPsfIndexFromBuffer__18005aba8`)
- [ ] **Embedded CIX may be delta-compressed and/or encrypted** before parse:
      detect `PA30/PA31/PA19` prefix and expand; honor container
      `encryptionType` (decrypt first). (`ProvideContainerIndex__18005af50`)
- [ ] **Hashes are arrays, not one.** `CixHash` = `{alg, value, norm
      (plain/PA19/PA30), normFlags, subrange offset, subrange length(-1=end),
      operation}`. ALG set: CRC32(0x20, custom table)/MD5/SHA1/SHA256/384/512.
      Today we keep one whole-stream SHA256 and **silently skip** other algs in
      verify — a latent hole. (`FromXml__18001a730`, `DpxValidateHash__180096648`)
- [ ] **`<Basis>` element + multi-`<Delta>`.** `Delta = {loc, Source, Basis}`;
      a target carries `Delta[]` (multi-source), not one. `loc` (attr 0x31)
      indexes into `<DeltaBasisSearch>`. `CixBasis = {length, targetRaw, loc,
      Hashes[]}`. (`FromXml__18001b294`, `FromXml__18002fea8`, `FromXml__18001ca74`)

## P1 — source/type fidelity
- [ ] **Source types**: add the WIM-compression family `LZX(1)/XPRESS(2)/
      XPRESSHUFF(3)/LZMS(4)`; keep `RAW(0)/PA19(0x13)/PA30(0x1e)`. **Drop PA31
      as a CIX source type** — it is only a PSF *blob* magic, never a
      `<Source type=>`. Accept both long (`CIX_SOURCE_PA30`) and short (`PA30`)
      spellings. (`CIX_SOURCE_TYPE_from_DPX_XML_STRING__18004d9ac`)
- [ ] **`CixSource` add `name`** (attr 0x25); offset/length are u64.
- [ ] **`CixContainer` add real `type` (UNK/CAB/PSF), version, length, and a
      container-level `Hashes[]`.** (`FromXml__180033490`)
- [ ] **`CixTarget` (File) add `time`, `attr`, `id`** (already partly modeled).

## P2 — basis-search + structural completeness
- [ ] Rename/extend `Location` -> `CixSearch{path, id, flags:u64 (hex)}`; add
      `CixAlias{targetName, aliasName}` and `CixSearchOption{filter}` under
      `<DeltaBasisSearch>`. (`FromXml__180010a8c`, `__18004f370`, `__18004f748`)
- [ ] (only if we ingest DPX `job.xml`) the outer-manifest layer: `CContainer`
      (encryptionType, peerGroupId, DecryptionData, RequestedRanges) + `CFile`
      (solution verb + dependency index arrays) + `CHash`(algId). We read the
      PSF/CIX directly, so this is low priority. (`FromXml__1800129a8`, `__18001ab00`)

## Streaming (large PSFs)
- [ ] The `io` feature's `PsfReader` already pulls ranges from `Read+Seek`. For
      `msu`, the cleanest low-RSS path is to `mmap` the uncompressed PSF region
      and hand the slice to the existing zero-copy API. Keep both surfaces.
