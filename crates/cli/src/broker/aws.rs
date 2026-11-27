//! AWS Signature Version 4 behind the broker. The caller (`aws`, an SDK,
//! `curl --aws-sigv4`) signs with the run's placeholder key; the broker
//! checks that the `Credential=` names it, drops the caller's signature,
//! date, token and host, and signs the request again with the real key for
//! the route's upstream, region and service.
//!
//! The body is buffered (the route's `max_body_bytes`), so the new
//! signature always covers its SHA-256. An `aws-chunked` body
//! (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, `STREAMING-UNSIGNED-PAYLOAD-TRAILER`
//! and their `-TRAILER` forms) is decoded first: its chunk signatures were
//! made with the placeholder and mean nothing upstream, and its
//! `x-amz-checksum-*` trailers become ordinary signed headers.

use deadbolt_remote::sigv4::{self, AmzDate, Credentials, Scope};
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::{HeaderMap, Method};
use subtle::ConstantTimeEq;
use url::Url;

use super::hygiene;
use super::proxy::Refusal;

/// Headers of the caller's signature, which never go upstream.
const CALLER_SIGNING: [&str; 6] = [
    "authorization",
    "x-amz-date",
    "x-amz-security-token",
    "x-amz-content-sha256",
    "x-amz-decoded-content-length",
    "x-amz-trailer",
];

pub struct SigV4 {
    placeholder: String,
    credentials: Credentials,
    region: String,
    service: String,
}

/// The key id in a SigV4 `Authorization` header's `Credential=`.
pub fn credential_key(authorization: &str) -> Option<&str> {
    let rest = authorization.strip_prefix("AWS4-HMAC-SHA256")?;
    rest.split(',')
        .find_map(|part| part.trim().strip_prefix("Credential="))
        .and_then(|credential| credential.split('/').next())
}

/// A query's parameters, decoded. A parameter named `X-Amz-*` once decoded
/// (`%58-Amz-Security-Token`, `x-amz-%65xpires`) is refused: those are a
/// presigned URL's, and the broker signs with headers only.
fn parameters(query: &str) -> Result<Vec<(String, String)>, Refusal> {
    let text = |part: &str| {
        String::from_utf8(hygiene::decode(part))
            .map_err(|_| Refusal::bad_request("a query parameter isn't UTF-8"))
    };
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let name = text(name)?;
            if name
                .get(..6)
                .is_some_and(|start| start.eq_ignore_ascii_case("x-amz-"))
            {
                return Err(Refusal::forbidden("presigned requests aren't brokered"));
            }
            Ok((name, text(value)?))
        })
        .collect()
}

fn line(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = bytes.windows(2).position(|pair| pair == b"\r\n")?;
    Some((&bytes[..at], &bytes[at + 2..]))
}

/// A decoded `aws-chunked` body: its payload and trailers.
pub type Unchunked = (Vec<u8>, Vec<(String, String)>);

/// Where a re-signed request goes: the route's upstream, the path after
/// its alias, and the caller's query.
pub struct Target<'a> {
    pub upstream: &'a Url,
    pub rest: &'a str,
    pub query: Option<&'a str>,
}

/// An `aws-chunked` body's payload and trailers (names lower case). The
/// trailers must end with an empty line, and nothing may follow it.
pub fn decode_aws_chunked(body: &[u8]) -> Result<Unchunked, &'static str> {
    let mut payload = Vec::with_capacity(body.len());
    let mut trailers = Vec::new();
    let mut rest = body;
    loop {
        let (head, after) = line(rest).ok_or("an aws-chunked chunk header without CRLF")?;
        let size = head.split(|b| *b == b';').next().unwrap_or_default();
        let size = std::str::from_utf8(size)
            .ok()
            .and_then(|size| usize::from_str_radix(size.trim(), 16).ok())
            .ok_or("an aws-chunked chunk size isn't hex")?;
        rest = after;
        if size == 0 {
            loop {
                let (field, after) =
                    line(rest).ok_or("an aws-chunked body doesn't end with an empty line")?;
                rest = after;
                if field.is_empty() {
                    break;
                }
                let field =
                    std::str::from_utf8(field).map_err(|_| "an aws-chunked trailer isn't text")?;
                let (name, value) = field
                    .split_once(':')
                    .ok_or("an aws-chunked trailer isn't name:value")?;
                trailers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
            if !rest.is_empty() {
                return Err("bytes follow an aws-chunked body's end");
            }
            return Ok((payload, trailers));
        }
        let Some(end) = size.checked_add(2) else {
            return Err("an aws-chunked chunk is cut short");
        };
        if rest.len() < end || &rest[size..end] != b"\r\n" {
            return Err("an aws-chunked chunk is cut short");
        }
        payload.extend_from_slice(&rest[..size]);
        rest = &rest[end..];
    }
}

fn text(value: &HeaderValue) -> Result<&str, Refusal> {
    value
        .to_str()
        .map_err(|_| Refusal::bad_request("a header the signature covers isn't text"))
}

impl SigV4 {
    pub fn new(
        placeholder: &str,
        access_key: &str,
        secret_key: &str,
        session_token: Option<&str>,
        region: &str,
        service: &str,
    ) -> Self {
        let mut credentials = Credentials::new(access_key, secret_key);
        if let Some(token) = session_token {
            credentials = credentials.with_session_token(token);
        }
        Self {
            placeholder: placeholder.to_string(),
            credentials,
            region: region.to_string(),
            service: service.to_string(),
        }
    }

    /// Whether the caller signed with this run's placeholder key, in an
    /// `Authorization` header (presigned URLs aren't brokered).
    pub fn check_caller(&self, headers: &HeaderMap, query: Option<&str>) -> Result<(), Refusal> {
        parameters(query.unwrap_or_default())?;
        let key = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(credential_key)
            .unwrap_or_default();
        if bool::from(key.as_bytes().ct_eq(self.placeholder.as_bytes())) {
            Ok(())
        } else {
            Err(Refusal::forbidden(
                "the request isn't signed with this route's placeholder key",
            ))
        }
    }

    /// Re-signs the request for `target`: rewrites `headers` and returns
    /// the URL and body to send.
    pub fn resign(
        &self,
        method: &Method,
        target: Target<'_>,
        headers: &mut HeaderMap,
        mut body: Vec<u8>,
        now: u64,
    ) -> Result<(Url, Vec<u8>), Refusal> {
        let Target {
            upstream,
            rest,
            query,
        } = target;
        let streaming = headers
            .get("x-amz-content-sha256")
            .is_some_and(|value| value.as_bytes().starts_with(b"STREAMING-"));
        if streaming {
            let (payload, trailers) = decode_aws_chunked(&body).map_err(Refusal::bad_request)?;
            let declared = headers
                .get("x-amz-decoded-content-length")
                .map(|value| {
                    value
                        .to_str()
                        .ok()
                        .and_then(|value| value.parse::<usize>().ok())
                        .ok_or(Refusal::bad_request(
                            "x-amz-decoded-content-length isn't a length",
                        ))
                })
                .transpose()?;
            if declared.is_some_and(|length| length != payload.len()) {
                return Err(Refusal::bad_request(
                    "x-amz-decoded-content-length doesn't match the body",
                ));
            }
            body = payload;
            for (name, value) in trailers {
                if name.starts_with("x-amz-checksum-")
                    && let (Ok(name), Ok(value)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_str(&value),
                    )
                {
                    headers.insert(name, value);
                }
            }
            let encodings = headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|e| !e.is_empty() && !e.eq_ignore_ascii_case("aws-chunked"))
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            match HeaderValue::from_str(&encodings) {
                Ok(value) if !encodings.is_empty() => {
                    headers.insert(header::CONTENT_ENCODING, value);
                }
                _ => {
                    headers.remove(header::CONTENT_ENCODING);
                }
            }
        }
        for name in CALLER_SIGNING {
            headers.remove(name);
        }

        let base = String::from_utf8(hygiene::decode(upstream.path().trim_end_matches('/')));
        let rest = String::from_utf8(hygiene::decode(rest));
        let (Ok(base), Ok(rest)) = (base, rest) else {
            return Err(Refusal::bad_request("the path isn't UTF-8"));
        };
        let wire_path = sigv4::uri_encode(&format!("{base}{rest}"), true);
        // S3 signs the path as sent; every other service encodes it again.
        let canonical_path = if self.service == "s3" {
            wire_path.clone()
        } else {
            sigv4::uri_encode(&wire_path, true)
        };
        let query = parameters(query.unwrap_or_default())?;
        let query_text = sigv4::canonical_query(&query);
        let mut url = upstream.clone();
        url.set_path(&wire_path);
        url.set_query((!query_text.is_empty()).then_some(query_text.as_str()));
        let host = match (url.host_str(), url.port()) {
            (Some(host), Some(port)) => format!("{host}:{port}"),
            (Some(host), None) => host.to_string(),
            (None, _) => return Err(Refusal::bad_request("the upstream has no host")),
        };

        let payload_hash = sigv4::sha256_hex(&body);
        let date = AmzDate::from_unix(now);
        let mut signed = sigv4::base_headers(&self.credentials, &host, &date, &payload_hash);
        for (name, value) in headers.iter() {
            let name = name.as_str();
            if name.starts_with("x-amz-") || name == "content-type" || name == "content-md5" {
                signed.push((name.to_string(), text(value)?.to_string()));
            }
        }
        let scope = Scope {
            region: &self.region,
            service: &self.service,
        };
        let signature = sigv4::sign(
            &self.credentials,
            &date,
            &scope,
            &sigv4::Request {
                method: method.as_str(),
                path: &canonical_path,
                query: &query,
                headers: &signed,
                payload_hash: &payload_hash,
            },
        );
        for (name, value) in &signed {
            if name == "host" || headers.contains_key(name.as_str()) {
                continue;
            }
            let (Ok(name), Ok(mut value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) else {
                return Err(Refusal::bad_request("a signed header isn't valid"));
            };
            value.set_sensitive(name.as_str() == "x-amz-security-token");
            headers.insert(name, value);
        }
        let mut authorization = HeaderValue::from_str(&signature.authorization)
            .map_err(|_| Refusal::bad_request("the signature isn't a valid header"))?;
        authorization.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, authorization);
        Ok((url, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_credential_names_the_key() {
        let value = "AWS4-HMAC-SHA256 Credential=db_ph_abc/20261125/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=00";
        assert_eq!(credential_key(value), Some("db_ph_abc"));
        assert_eq!(credential_key("Bearer x"), None);
        assert_eq!(credential_key("AWS4-HMAC-SHA256 SignedHeaders=host"), None);
    }

    #[test]
    fn aws_chunked_bodies_decode_with_their_trailers() {
        let body = b"5;chunk-signature=aaaa\r\nhello\r\n6;chunk-signature=bbbb\r\n world\r\n0;chunk-signature=cccc\r\n\r\n";
        let (payload, trailers) = decode_aws_chunked(body).unwrap();
        assert_eq!(payload, b"hello world");
        assert!(trailers.is_empty());

        let body = b"b\r\nhello world\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\nx-amz-trailer-signature:abc\r\n\r\n";
        let (payload, trailers) = decode_aws_chunked(body).unwrap();
        assert_eq!(payload, b"hello world");
        assert_eq!(
            trailers[0],
            ("x-amz-checksum-crc32".into(), "DUoRhQ==".into())
        );

        for bad in [&b"zz\r\nx"[..], b"5\r\nhel", b"5\r\nhelloXX0\r\n\r\n", b"5"] {
            assert!(decode_aws_chunked(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_aws_chunked_body_must_end_cleanly() {
        for bad in [
            // No empty line after the last chunk or its trailers.
            &b"5\r\nhello\r\n0\r\n"[..],
            b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAA\r\n",
            // Bytes smuggled after the end.
            b"5\r\nhello\r\n0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\nx",
        ] {
            assert!(decode_aws_chunked(bad).is_err(), "{bad:?}");
        }
        assert!(decode_aws_chunked(b"5\r\nhello\r\n0\r\n\r\n").is_ok());
    }

    #[test]
    fn an_oversized_chunk_is_refused_without_overflow() {
        assert!(decode_aws_chunked(b"ffffffffffffffff\r\nX").is_err());
    }

    #[test]
    fn x_amz_query_parameters_are_refused_however_they_are_escaped() {
        for query in [
            "X-Amz-Credential=x",
            "%58-Amz-Security-Token=x",
            "x-amz-%65xpires=60",
            "a=1&%78%2D%61%6D%7A%2Dsignature=00",
        ] {
            let refused = parameters(query).unwrap_err();
            assert_eq!(refused.status, hyper::StatusCode::FORBIDDEN, "{query}");
        }
        assert_eq!(
            parameters("list-type=2&prefix=a%2Fb").unwrap(),
            [
                ("list-type".to_string(), "2".to_string()),
                ("prefix".to_string(), "a/b".to_string())
            ]
        );
    }
}
