//! `PROPFIND` `207 Multi-Status` parsing, tolerant of every namespace
//! prefix servers use (`D:`, `d:`, a default namespace, none).

use crate::error::RemoteError;
use crate::xml;

/// The request body: ask only for `resourcetype`.
pub const PROPFIND_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>"#;

/// One `<response>`: its raw `href`s and whether it is a collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DavEntry {
    /// Every `<href>` the response names (RFC 4918 allows several when it
    /// carries a response-level `<status>`).
    pub hrefs: Vec<String>,
    /// True when a `2xx` `<propstat>` reports `<collection/>`.
    pub is_collection: bool,
}

#[derive(Default)]
struct Response {
    hrefs: Vec<String>,
    status: Option<u16>,
    is_collection: bool,
    propstat_collection: bool,
    propstat_status: Option<u16>,
}

/// The code of a `<status>` line such as `HTTP/1.1 404 Not Found`.
fn status_code(text: &str) -> Result<u16, RemoteError> {
    text.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| RemoteError::Protocol(format!("bad WebDAV status line {:?}", text.trim())))
}

/// Parses a `multistatus` body into its found responses, in document order.
/// A `404` (or other non-success) response is skipped; a `401`, `403` or
/// `5xx` response is an error, since skipping it would hide objects.
pub fn parse_multistatus(body: &str) -> Result<Vec<DavEntry>, RemoteError> {
    let mut entries = Vec::new();
    let mut current = Response::default();
    let mut root_seen = false;
    xml::walk(body, |path, text| {
        let names: Vec<&str> = path.iter().map(String::as_str).collect();
        match names.as_slice() {
            ["multistatus"] => root_seen = true,
            ["multistatus", "response", "href"] => current.hrefs.push(text.trim().to_owned()),
            ["multistatus", "response", "status"] => current.status = Some(status_code(text)?),
            ["multistatus", "response", "propstat", "status"] => {
                current.propstat_status = Some(status_code(text)?);
            }
            [
                "multistatus",
                "response",
                "propstat",
                "prop",
                "resourcetype",
                "collection",
            ] => {
                current.propstat_collection = true;
            }
            ["multistatus", "response", "propstat"] => {
                // A propstat without a status is read as found.
                let found = current
                    .propstat_status
                    .take()
                    .is_none_or(|s| (200..300).contains(&s));
                if std::mem::take(&mut current.propstat_collection) && found {
                    current.is_collection = true;
                }
            }
            ["multistatus", "response"] => {
                let response = std::mem::take(&mut current);
                if response.hrefs.is_empty() || response.hrefs.iter().any(String::is_empty) {
                    return Err(RemoteError::Protocol(
                        "PROPFIND response without href".into(),
                    ));
                }
                match response.status {
                    Some(status @ (401 | 403 | 500..)) => {
                        return Err(RemoteError::Status {
                            verb: "PROPFIND",
                            name: response.hrefs.join(" "),
                            status,
                        });
                    }
                    Some(status) if !(200..300).contains(&status) => {}
                    _ => entries.push(DavEntry {
                        hrefs: response.hrefs,
                        is_collection: response.is_collection,
                    }),
                }
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
