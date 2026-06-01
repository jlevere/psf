//! The Container Index (CIX) -- `express.psf.cix.xml`, the manifest that
//! indexes a PSTREAM container.
//!
//! Reference: `dpx.dll` `CContainer::FromXml` / `ProvideContainerIndex` /
//! `LinkCixTargets`. The CIX maps each target file to its source stream in the
//! `.psf`: either a `RAW` byte range (the file stored verbatim) or a
//! `PA30`/`PA31` MSDelta blob, with SHA256s for both the source stream and the
//! reconstructed target. `DeltaBasisSearch` lists where basis (source) files
//! live for non-baseless deltas; a "baseless" container's deltas reconstruct
//! from a null base.

use yaserde_derive::YaDeserialize;

use crate::{Error, PsfStream, Result};

const CI: &str = "urn:ContainerIndex";

/// A digest from the CIX (typically SHA256).
#[derive(YaDeserialize, Default, Debug, Clone, PartialEq, Eq)]
#[yaserde(rename = "Hash", prefix = "ci", default_namespace = "ci", namespaces = { "ci" = "urn:ContainerIndex" })]
pub struct Hash {
    #[yaserde(attribute = true, rename = "alg")]
    pub alg: String,
    #[yaserde(attribute = true, rename = "value")]
    pub value: String,
}

/// A file's source stream: where its bytes live in the `.psf` and how to read
/// them (`RAW` stored bytes, or a `PA30`/`PA31`/`PA19` MSDelta).
#[derive(YaDeserialize, Default, Debug, Clone)]
#[yaserde(rename = "Source", prefix = "ci", default_namespace = "ci", namespaces = { "ci" = "urn:ContainerIndex" })]
pub struct Source {
    #[yaserde(attribute = true, rename = "type")]
    pub kind: String,
    #[yaserde(attribute = true, rename = "offset")]
    pub offset: u64,
    #[yaserde(attribute = true, rename = "length")]
    pub length: u64,
    /// SHA256 of the source bytes (the stored bytes or the delta itself).
    #[yaserde(rename = "Hash", prefix = "ci")]
    pub hash: Option<Hash>,
}

impl Source {
    /// `true` for a `PA30`/`PA31`/`PA19` MSDelta source (vs `RAW`).
    pub fn is_delta(&self) -> bool {
        self.kind.starts_with("PA")
    }
    pub fn stream(&self) -> PsfStream {
        PsfStream {
            offset: self.offset,
            length: self.length,
        }
    }
}

#[derive(YaDeserialize, Default, Debug, Clone)]
#[yaserde(rename = "Delta", prefix = "ci", default_namespace = "ci", namespaces = { "ci" = "urn:ContainerIndex" })]
pub struct Delta {
    #[yaserde(rename = "Source", prefix = "ci")]
    pub source: Source,
}

/// A target file the container reconstructs.
#[derive(YaDeserialize, Default, Debug, Clone)]
#[yaserde(rename = "File", prefix = "ci", default_namespace = "ci", namespaces = { "ci" = "urn:ContainerIndex" })]
pub struct File {
    #[yaserde(attribute = true, rename = "id")]
    pub id: u32,
    #[yaserde(attribute = true, rename = "name")]
    pub name: String,
    #[yaserde(attribute = true, rename = "length")]
    pub length: u64,
    /// Target file timestamp (FILETIME ticks); kept verbatim.
    #[yaserde(attribute = true, rename = "time")]
    pub time: String,
    #[yaserde(attribute = true, rename = "attr")]
    pub attr: String,
    /// SHA256 of the reconstructed target file.
    #[yaserde(rename = "Hash", prefix = "ci")]
    pub hash: Option<Hash>,
    #[yaserde(rename = "Delta", prefix = "ci")]
    pub delta: Option<Delta>,
}

impl File {
    /// The byte range of this file's source stream within the `.psf`.
    pub fn psf_stream(&self) -> Option<PsfStream> {
        self.delta.as_ref().map(|d| d.source.stream())
    }
    pub fn source(&self) -> Option<&Source> {
        self.delta.as_ref().map(|d| &d.source)
    }
}

#[derive(YaDeserialize, Default, Debug, Clone)]
#[yaserde(rename = "Files", prefix = "ci", default_namespace = "ci", namespaces = { "ci" = "urn:ContainerIndex" })]
pub struct Files {
    #[yaserde(rename = "File", prefix = "ci")]
    pub file: Vec<File>,
}

/// A basis-search location (where source files for non-baseless deltas live).
#[derive(YaDeserialize, Default, Debug, Clone)]
#[yaserde(rename = "Location", prefix = "ci", default_namespace = "ci", namespaces = { "ci" = "urn:ContainerIndex" })]
pub struct Location {
    #[yaserde(attribute = true, rename = "id")]
    pub id: u32,
    #[yaserde(attribute = true, rename = "path")]
    pub path: String,
    #[yaserde(attribute = true, rename = "flags")]
    pub flags: String,
}

#[derive(YaDeserialize, Default, Debug, Clone)]
#[yaserde(rename = "DeltaBasisSearch", prefix = "ci", default_namespace = "ci", namespaces = { "ci" = "urn:ContainerIndex" })]
pub struct DeltaBasisSearch {
    #[yaserde(rename = "Location", prefix = "ci")]
    pub location: Vec<Location>,
}

/// A parsed Container Index (`express.psf.cix.xml`).
#[derive(YaDeserialize, Default, Debug, Clone)]
#[yaserde(rename = "Container", prefix = "ci", default_namespace = "ci", namespaces = { "ci" = "urn:ContainerIndex" })]
pub struct ContainerIndex {
    #[yaserde(attribute = true, rename = "name")]
    pub name: String,
    #[yaserde(attribute = true, rename = "type")]
    pub kind: String,
    #[yaserde(attribute = true, rename = "length")]
    pub length: u64,
    #[yaserde(attribute = true, rename = "version")]
    pub version: String,
    #[yaserde(rename = "DeltaBasisSearch", prefix = "ci")]
    pub delta_basis_search: Option<DeltaBasisSearch>,
    #[yaserde(rename = "Files", prefix = "ci")]
    pub files: Files,
}

impl ContainerIndex {
    /// Parse a CIX (`express.psf.cix.xml`) document.
    pub fn parse(xml: &str) -> Result<Self> {
        let _ = CI;
        yaserde::de::from_str(xml).map_err(Error::Cix)
    }

    pub fn files(&self) -> &[File] {
        &self.files.file
    }

    /// Whether the container is baseless (deltas reconstruct from a null base,
    /// no basis file needed).
    pub fn is_baseless(&self) -> bool {
        self.name.contains("baseless")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = concat!(
        r#"<?xml version="1.0" encoding="utf-8"?>"#,
        r#"<Container name="kb-baseless.psf" type="PSF" length="100" version="1" xmlns="urn:ContainerIndex">"#,
        r#"<DeltaBasisSearch><Location id="0" path="{windir}\servicing\packages" flags="2000001" /></DeltaBasisSearch>"#,
        r#"<Files>"#,
        r#"<File id="1" name="a.dll" length="11776" time="134225614730000000" attr="128">"#,
        r#"<Hash alg="SHA256" value="AABB" />"#,
        r#"<Delta><Source type="PA30" offset="3276800" length="4595"><Hash alg="SHA256" value="CCDD" /></Source></Delta>"#,
        r#"</File>"#,
        r#"<File id="2" name="b.txt" length="5" time="0" attr="128">"#,
        r#"<Hash alg="SHA256" value="EEFF" />"#,
        r#"<Delta><Source type="RAW" offset="100" length="5" /></Delta>"#,
        r#"</File>"#,
        r#"</Files></Container>"#,
    );

    #[test]
    fn parses_container_index() {
        let cix = ContainerIndex::parse(SAMPLE).unwrap();
        assert_eq!(cix.kind, "PSF");
        assert_eq!(cix.length, 100);
        assert!(cix.is_baseless());
        assert_eq!(cix.delta_basis_search.as_ref().unwrap().location.len(), 1);

        let files = cix.files();
        assert_eq!(files.len(), 2);

        let a = &files[0];
        assert_eq!(a.name, "a.dll");
        assert_eq!(a.length, 11776);
        assert_eq!(a.hash.as_ref().unwrap().value, "AABB");
        let sa = a.source().unwrap();
        assert!(sa.is_delta());
        assert_eq!(sa.kind, "PA30");
        assert_eq!(a.psf_stream(), Some(PsfStream { offset: 3276800, length: 4595 }));
        assert_eq!(sa.hash.as_ref().unwrap().value, "CCDD");

        let b = &files[1];
        let sb = b.source().unwrap();
        assert!(!sb.is_delta());
        assert_eq!(sb.kind, "RAW");
        assert_eq!(b.psf_stream(), Some(PsfStream { offset: 100, length: 5 }));
    }

    // Real CIX: `UUP_CIX=/path/to/express.psf.cix.xml cargo test -p psf -- --nocapture`.
    #[test]
    fn real_cix_fixture() {
        let Ok(path) = std::env::var("UUP_CIX") else {
            eprintln!("skip: set UUP_CIX to a real express.psf.cix.xml");
            return;
        };
        let xml = std::fs::read_to_string(path).unwrap();
        let cix = ContainerIndex::parse(&xml).unwrap();
        let files = cix.files();
        let raw = files.iter().filter(|f| f.source().is_some_and(|s| !s.is_delta())).count();
        let delta = files.iter().filter(|f| f.source().is_some_and(|s| s.is_delta())).count();
        eprintln!(
            "container={:?} baseless={} files={} (raw={raw} delta={delta})",
            cix.name,
            cix.is_baseless(),
            files.len()
        );
        assert!(!files.is_empty());
        assert!(files.iter().all(|f| f.hash.is_some() && f.psf_stream().is_some()));
    }
}
