//! Strict HTTP: a request the broker forwards has one canonical path, a
//! clean query, no repeated framing or credential headers, and nothing
//! hop-by-hop. Anything ambiguous is refused, not repaired: an upstream
//! might read it differently than the broker did.

use hyper::HeaderMap;
use hyper::header::{self, HeaderName};

/// Headers that belong to one connection, never forwarded (RFC 9110 §7.6.1,
/// plus `Proxy-*` and `Keep-Alive`).
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

/// Headers a request may carry once at most.
const SINGLE: [&str; 9] = [
    "authorization",
    "host",
    "content-length",
    "transfer-encoding",
    "content-encoding",
    "x-amz-date",
    "x-amz-content-sha256",
    "x-amz-security-token",
    "x-amz-decoded-content-length",
];

/// Headers the broker sets itself, which can't carry a route's secret.
pub fn is_reserved(name: &str) -> bool {
    HOP_BY_HOP.contains(&name)
        || matches!(
            name,
            "host" | "content-length" | "transfer-encoding" | "expect" | "cookie"
        )
        || name.starts_with("proxy-")
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Visible ASCII with well-formed escapes, each escape's byte passing
/// `escaped`.
fn clean(text: &str, escaped: impl Fn(u8) -> bool) -> Result<(), &'static str> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let (Some(hi), Some(lo)) = (
                    bytes.get(i + 1).copied().and_then(hex),
                    bytes.get(i + 2).copied().and_then(hex),
                ) else {
                    return Err("a broken %-escape");
                };
                let byte = hi << 4 | lo;
                if byte < 0x20 || byte == 0x7f || !escaped(byte) {
                    return Err("an escaped dot, slash, backslash or control character");
                }
                i += 3;
            }
            b'\\' | b'#' => return Err("a backslash or fragment"),
            0x21..=0x7e => i += 1,
            _ => return Err("a space, control or non-ASCII character"),
        }
    }
    Ok(())
}

/// A canonical path: starts with `/`, no empty, `.` or `..` segment (a
/// trailing `/` aside), no `;` parameters, and no escape that decodes to
/// `.`, `/`, `\\` or a control character.
pub fn check_path(path: &str) -> Result<(), &'static str> {
    let Some(rest) = path.strip_prefix('/') else {
        return Err("not absolute");
    };
    clean(path, |b| !matches!(b, b'.' | b'/' | b'\\'))?;
    if path.contains(';') {
        return Err("a ;-parameter");
    }
    let segments: Vec<&str> = rest.split('/').collect();
    let last = segments.len() - 1;
    for (n, segment) in segments.iter().enumerate() {
        if (segment.is_empty() && n != last) || *segment == "." || *segment == ".." {
            return Err("an empty, . or .. segment");
        }
    }
    Ok(())
}

/// A query the broker passes on: visible ASCII, well-formed escapes, no
/// escaped control character.
pub fn check_query(query: &str) -> Result<(), &'static str> {
    clean(query, |_| true)
}

/// `/<alias>/<rest>` as `(alias, "/<rest>")`; `/<alias>` alone is `/`.
pub fn split_alias(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix('/')?;
    match rest.find('/') {
        Some(at) => Some((&rest[..at], &rest[at..])),
        None => Some((rest, "/")),
    }
}

/// Percent-decoded, for paths and query parts already checked.
pub fn decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let (Some(hi), Some(lo)) = (
                bytes.get(i + 1).copied().and_then(hex),
                bytes.get(i + 2).copied().and_then(hex),
            )
        {
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// `*` matches within one segment, `**` any number of whole segments.
pub fn glob_match(glob: &str, path: &str) -> bool {
    let glob: Vec<&str> = glob.split('/').collect();
    let path: Vec<&str> = path.split('/').collect();
    segments_match(&glob, &path)
}

fn segments_match(glob: &[&str], path: &[&str]) -> bool {
    match glob.split_first() {
        None => path.is_empty(),
        Some((&"**", rest)) => (0..=path.len()).any(|skip| segments_match(rest, &path[skip..])),
        Some((first, rest)) => path.split_first().is_some_and(|(segment, more)| {
            segment_match(first, segment) && segments_match(rest, more)
        }),
    }
}

fn segment_match(glob: &str, text: &str) -> bool {
    match glob.split_once('*') {
        None => glob == text,
        Some((head, tail)) => {
            let Some(text) = text.strip_prefix(head) else {
                return false;
            };
            (0..=text.len())
                .filter(|at| text.is_char_boundary(*at))
                .any(|at| segment_match(tail, &text[at..]))
        }
    }
}

/// Whether a route with these `prefixes` and `globs` allows `rest`, the
/// path after its alias.
pub fn path_allowed(prefixes: &[String], globs: &[String], rest: &str) -> bool {
    if prefixes.is_empty() && globs.is_empty() {
        return true;
    }
    prefixes.iter().any(|prefix| {
        let prefix = prefix.trim_end_matches('/');
        prefix.is_empty()
            || rest == prefix
            || rest
                .strip_prefix(prefix)
                .is_some_and(|after| after.starts_with('/'))
    }) || globs.iter().any(|glob| glob_match(glob, rest))
}

/// Refuses repeated framing and credential headers (and `extra`, the
/// route's own secret header), and a body framed two ways.
pub fn check_headers(headers: &HeaderMap, extra: Option<&str>) -> Result<(), &'static str> {
    for name in SINGLE.iter().copied().chain(extra) {
        if headers.get_all(name).iter().count() > 1 {
            return Err("a repeated Authorization, Host, framing or signing header");
        }
    }
    if headers.contains_key(header::CONTENT_LENGTH)
        && headers.contains_key(header::TRANSFER_ENCODING)
    {
        return Err("both Content-Length and Transfer-Encoding");
    }
    Ok(())
}

/// Drops hop-by-hop headers, and any header `Connection` names.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    headers.remove(header::TRANSFER_ENCODING);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_must_be_canonical() {
        for good in [
            "/",
            "/v1",
            "/v1/",
            "/v1/chat/completions",
            "/b/key%20with%20space",
            "/a%25b",
        ] {
            assert_eq!(check_path(good), Ok(()), "{good}");
        }
        for bad in [
            "",
            "v1",
            "//admin",
            "/v1//x",
            "/v1/../admin",
            "/v1/./x",
            "/..",
            "/v1/%2e%2e/admin",
            "/v1/%2E%2E/admin",
            "/v1%2fadmin",
            "/v1%2Fadmin",
            "/v1%5cadmin",
            "/v1%00",
            "/v1/%0a",
            "/v1\\admin",
            "/v1;x=1",
            "/v1/%zz",
            "/v1/%2",
            "/v1#frag",
            "/v1/é",
            "/v1 x",
        ] {
            assert!(check_path(bad).is_err(), "{bad:?}");
        }
        assert!(check_query("a=1&b=%20x&uploads").is_ok());
        for bad in ["a=%00", "a=%0d%0aX:1", "a=\n", "a b", "a=%g1"] {
            assert!(check_query(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn globs_match_segments() {
        assert!(glob_match("/v1/*/chat", "/v1/abc/chat"));
        assert!(!glob_match("/v1/*/chat", "/v1/a/b/chat"));
        assert!(glob_match("/v1/**", "/v1"));
        assert!(glob_match("/v1/**", "/v1/a/b"));
        assert!(glob_match("/v1/**/x", "/v1/a/b/x"));
        assert!(glob_match("/files/*.txt", "/files/a.txt"));
        assert!(!glob_match("/files/*.txt", "/files/a.txt/b"));
        assert!(!glob_match("/v1/*", "/admin"));
    }

    #[test]
    fn aliases_split_off() {
        assert_eq!(split_alias("/openai/v1/chat"), Some(("openai", "/v1/chat")));
        assert_eq!(split_alias("/openai"), Some(("openai", "/")));
        assert_eq!(split_alias("/openai/"), Some(("openai", "/")));
        assert_eq!(decode("/a%20b%2B"), b"/a b+");
    }

    #[test]
    fn repeated_framing_headers_and_hop_by_hop() {
        let mut headers = HeaderMap::new();
        headers.append("authorization", "a".parse().unwrap());
        assert!(check_headers(&headers, None).is_ok());
        headers.append("authorization", "b".parse().unwrap());
        assert!(check_headers(&headers, None).is_err());

        let mut headers = HeaderMap::new();
        headers.append("x-api-key", "a".parse().unwrap());
        headers.append("x-api-key", "b".parse().unwrap());
        assert!(check_headers(&headers, None).is_ok());
        assert!(check_headers(&headers, Some("x-api-key")).is_err());

        let mut headers = HeaderMap::new();
        headers.insert("content-length", "1".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        assert!(check_headers(&headers, None).is_err());

        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("connection", "keep-alive, x-secret-hop"),
            ("x-secret-hop", "1"),
            ("keep-alive", "5"),
            ("proxy-authorization", "x"),
            ("upgrade", "h2c"),
            ("te", "trailers"),
            ("accept", "*/*"),
        ] {
            headers.insert(name, value.parse().unwrap());
        }
        strip_hop_by_hop(&mut headers);
        let left: Vec<&str> = headers.keys().map(HeaderName::as_str).collect();
        assert_eq!(left, ["accept"]);
    }
}
