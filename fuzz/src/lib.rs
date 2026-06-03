//! Structure-aware input for the CIX fuzzer: an `Arbitrary`-driven model of a
//! Container Index that renders to well-formed XML.
//!
//! Raw byte mutation almost never produces a valid manifest, so it never
//! reaches the parser's interesting paths (nesting, optional/repeated elements,
//! entity escaping). Generating from a typed model guarantees every input is a
//! well-formed CIX document, and -- because the model is the ground truth --
//! lets the target round-trip-check that the parser reads back exactly what was
//! written, not merely that it didn't panic.

use arbitrary::{Arbitrary, Unstructured};
use std::fmt::Write;

/// XML-attribute-safe text. Drawn from printable ASCII minus the characters
/// subject to attribute-value normalization (tab/newline/CR, which collapse to
/// spaces and would break a faithful round-trip). Deliberately includes the
/// five predefined-entity characters so the escape/unescape round-trip is
/// exercised, and occasionally emits the literal "baseless" marker so the
/// `is_baseless` path gets hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Text(pub String);

const ALPHABET: &[u8] = b"abcABC012._-/\\{}:&<>\"'";

impl<'a> Arbitrary<'a> for Text {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.ratio(1, 8)? {
            return Ok(Text("kb-baseless.psf".to_string()));
        }
        let n = u.int_in_range(0..=20)?;
        let mut s = String::with_capacity(n);
        for _ in 0..n {
            s.push(*u.choose(ALPHABET)? as char);
        }
        Ok(Text(s))
    }
}

/// A source `type`, biased toward the real tokens so both the delta and RAW
/// branches (and the `PA`-prefix case sensitivity in `is_delta`) get covered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kind(pub String);

const KINDS: &[&str] = &[
    "PA30", "PA31", "PA19", "PA00", "RAW", "", "PARTIAL", "pa30", "XPRESS",
];

impl<'a> Arbitrary<'a> for Kind {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.ratio(7, 8)? {
            Ok(Kind((*u.choose(KINDS)?).to_string()))
        } else {
            Ok(Kind(Text::arbitrary(u)?.0))
        }
    }
}

#[derive(Arbitrary, Debug)]
pub struct HashNode {
    pub alg: Text,
    pub value: Text,
}

#[derive(Arbitrary, Debug)]
pub struct SourceNode {
    pub kind: Kind,
    pub offset: u64,
    pub length: u64,
    pub hash: Option<HashNode>,
}

#[derive(Arbitrary, Debug)]
pub struct DeltaNode {
    pub source: SourceNode,
}

#[derive(Arbitrary, Debug)]
pub struct FileNode {
    pub id: u32,
    pub name: Text,
    pub length: u64,
    pub time: Text,
    pub attr: Text,
    pub hash: Option<HashNode>,
    pub delta: Option<DeltaNode>,
}

#[derive(Arbitrary, Debug)]
pub struct LocationNode {
    pub id: u32,
    pub path: Text,
    pub flags: Text,
}

/// An `Arbitrary` Container Index that renders to a well-formed manifest.
#[derive(Arbitrary, Debug)]
pub struct CixDoc {
    pub name: Text,
    pub kind: Text,
    pub length: u64,
    pub version: Text,
    pub locations: Vec<LocationNode>,
    pub files: Vec<FileNode>,
}

impl CixDoc {
    /// Render to a well-formed `urn:ContainerIndex` document matching the
    /// schema the parser expects (default namespace, unprefixed elements).
    pub fn render(&self) -> String {
        let mut x = String::new();
        x.push_str(r#"<?xml version="1.0" encoding="utf-8"?>"#);
        write!(
            x,
            r#"<Container name="{}" type="{}" length="{}" version="{}" xmlns="urn:ContainerIndex">"#,
            esc(&self.name.0),
            esc(&self.kind.0),
            self.length,
            esc(&self.version.0),
        )
        .unwrap();

        if !self.locations.is_empty() {
            x.push_str("<DeltaBasisSearch>");
            for l in &self.locations {
                write!(
                    x,
                    r#"<Location id="{}" path="{}" flags="{}" />"#,
                    l.id,
                    esc(&l.path.0),
                    esc(&l.flags.0),
                )
                .unwrap();
            }
            x.push_str("</DeltaBasisSearch>");
        }

        x.push_str("<Files>");
        for f in &self.files {
            write!(
                x,
                r#"<File id="{}" name="{}" length="{}" time="{}" attr="{}">"#,
                f.id,
                esc(&f.name.0),
                f.length,
                esc(&f.time.0),
                esc(&f.attr.0),
            )
            .unwrap();
            if let Some(h) = &f.hash {
                write_hash(&mut x, h);
            }
            if let Some(d) = &f.delta {
                let s = &d.source;
                write!(
                    x,
                    r#"<Delta><Source type="{}" offset="{}" length="{}">"#,
                    esc(&s.kind.0),
                    s.offset,
                    s.length,
                )
                .unwrap();
                if let Some(h) = &s.hash {
                    write_hash(&mut x, h);
                }
                x.push_str("</Source></Delta>");
            }
            x.push_str("</File>");
        }
        x.push_str("</Files></Container>");
        x
    }
}

fn write_hash(x: &mut String, h: &HashNode) {
    write!(
        x,
        r#"<Hash alg="{}" value="{}" />"#,
        esc(&h.alg.0),
        esc(&h.value.0),
    )
    .unwrap();
}

/// Escape the five XML predefined entities for attribute content.
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            _ => o.push(c),
        }
    }
    o
}
