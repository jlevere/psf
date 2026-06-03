#!/usr/bin/env bash
#
# Seed the fuzz corpora so coverage-guided fuzzing starts from valid artifacts
# instead of rediscovering the formats from scratch. Corpus dirs are gitignored;
# this script is idempotent and safe to re-run.
#
#   ./fuzz/seed_corpus.sh
#
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

mkdir -p "$here/corpus/fuzz_psf" "$here/corpus/fuzz_reader" "$here/corpus/fuzz_cix"

# CIX: a minimal but structurally complete manifest exercising both a PA30 delta
# and a RAW source. Always available, so the XML target has a valid seed on a
# fresh clone.
cat >"$here/corpus/fuzz_cix/sample.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<Container name="kb-baseless.psf" type="PSF" length="100" version="1" xmlns="urn:ContainerIndex">
<DeltaBasisSearch><Location id="0" path="{windir}\servicing\packages" flags="2000001" /></DeltaBasisSearch>
<Files>
<File id="1" name="a.dll" length="11776" time="134225614730000000" attr="128">
<Hash alg="SHA256" value="AABB" />
<Delta><Source type="PA30" offset="3276800" length="4595"><Hash alg="SHA256" value="CCDD" /></Source></Delta>
</File>
<File id="2" name="b.txt" length="5" time="0" attr="128">
<Hash alg="SHA256" value="EEFF" />
<Delta><Source type="RAW" offset="100" length="5" /></Delta>
</File>
</Files></Container>
XML

# PSTREAM byte targets: real .psf containers are gitignored and not redistributable.
# Seed from $UUP_PSF_FIXTURE and tests/fixtures when present; no-op otherwise.
seed_psf() {
  local f="$1"
  [ -e "$f" ] || return 0
  cp -f "$f" "$here/corpus/fuzz_psf/"
  cp -f "$f" "$here/corpus/fuzz_reader/"
}

[ -n "${UUP_PSF_FIXTURE:-}" ] && seed_psf "$UUP_PSF_FIXTURE"
if [ -d "$root/tests/fixtures" ]; then
  for f in "$root"/tests/fixtures/*.psf; do
    seed_psf "$f"
  done
fi

echo "seeded: $(find "$here/corpus" -type f | wc -l | tr -d ' ') corpus file(s)"
