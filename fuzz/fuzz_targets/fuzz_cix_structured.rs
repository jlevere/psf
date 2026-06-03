#![no_main]

use libfuzzer_sys::fuzz_target;
use psf::cix::ContainerIndex;
use psf_fuzz::CixDoc;

// Structure-aware round-trip oracle. The input is a typed CIX model rendered to
// well-formed XML, so this reaches the parser's deep paths that raw byte
// mutation never finds. Because the model is ground truth, the parser must (a)
// accept any well-formed manifest and (b) read back exactly what was written --
// a silent dropped or misparsed field fails here, not just a panic.
fuzz_target!(|doc: CixDoc| {
    let xml = doc.render();
    let cix = ContainerIndex::parse(&xml)
        .unwrap_or_else(|e| panic!("well-formed CIX failed to parse: {e}\n{xml}"));

    assert_eq!(cix.name, doc.name.0, "container name\n{xml}");
    assert_eq!(cix.kind, doc.kind.0, "container type\n{xml}");
    assert_eq!(cix.length, doc.length, "container length\n{xml}");
    assert_eq!(cix.version, doc.version.0, "container version\n{xml}");
    assert_eq!(
        cix.is_baseless(),
        doc.name.0.contains("baseless"),
        "is_baseless\n{xml}"
    );
    assert_eq!(cix.files().len(), doc.files.len(), "file count\n{xml}");

    for (f, m) in cix.files().iter().zip(&doc.files) {
        assert_eq!(f.id, m.id, "file id\n{xml}");
        assert_eq!(f.name, m.name.0, "file name\n{xml}");
        assert_eq!(f.length, m.length, "file length\n{xml}");
        assert_eq!(f.time, m.time.0, "file time\n{xml}");
        assert_eq!(f.attr, m.attr.0, "file attr\n{xml}");

        assert_eq!(
            f.hash.is_some(),
            m.hash.is_some(),
            "file hash presence\n{xml}"
        );
        if let (Some(h), Some(mh)) = (&f.hash, &m.hash) {
            assert_eq!(h.alg, mh.alg.0, "file hash alg\n{xml}");
            assert_eq!(h.value, mh.value.0, "file hash value\n{xml}");
        }

        match (f.source(), &m.delta) {
            (Some(src), Some(md)) => {
                assert_eq!(src.kind, md.source.kind.0, "source type\n{xml}");
                assert_eq!(src.offset, md.source.offset, "source offset\n{xml}");
                assert_eq!(src.length, md.source.length, "source length\n{xml}");
                assert_eq!(
                    src.is_delta(),
                    md.source.kind.0.starts_with("PA"),
                    "is_delta\n{xml}"
                );
                assert_eq!(f.psf_stream(), Some(src.stream()), "psf_stream\n{xml}");
            }
            (None, None) => {}
            (s, _) => panic!("delta presence mismatch (src={})\n{xml}", s.is_some()),
        }
    }
});
