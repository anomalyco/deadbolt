//! `PROPFIND` `207 Multi-Status` parsing, tolerant of every namespace
//! prefix servers use (`D:`, `d:`, a default namespace, none).

use crate::error::RemoteError;
use crate::xml;

/// The request body: ask only for `resourcetype`.
pub const PROPFIND_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>"#;

/// One `<response>`: its raw `href` and whether it is a collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DavEntry {
    pub href: String,
    pub is_collection: bool,
}

/// Parses a `multistatus` body into its responses, in document order.
pub fn parse_multistatus(body: &str) -> Result<Vec<DavEntry>, RemoteError> {
    let mut entries = Vec::new();
    let mut href = String::new();
    let mut is_collection = false;
    let mut root_seen = false;
    xml::walk(body, |path, text| {
        let names: Vec<&str> = path.iter().map(String::as_str).collect();
        match names.as_slice() {
            ["multistatus"] => root_seen = true,
            ["multistatus", "response", "href"] => href = text.to_owned(),
            ["multistatus", "response", .., "resourcetype", "collection"] => is_collection = true,
            ["multistatus", "response"] => {
                if href.is_empty() {
                    return Err(RemoteError::Protocol(
                        "PROPFIND response without href".into(),
                    ));
                }
                entries.push(DavEntry {
                    href: std::mem::take(&mut href),
                    is_collection: std::mem::take(&mut is_collection),
                });
            }
            _ => {}
        }
        Ok(())
    })?;
    if !root_seen {
        return Err(RemoteError::Protocol("not a WebDAV multistatus".into()));
    }
    Ok(entries)
}
