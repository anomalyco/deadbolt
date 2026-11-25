//! Published AWS vectors: the SigV4 test suite (`get-vanilla`), the S3
//! "Signature Calculations for the Authorization Header" and "Query String
//! Authentication" examples, and the signing-key derivation example.

use crate::path::hex;
use crate::s3::{Addressing, S3Config};
use crate::sigv4::{
    self, AmzDate, Credentials, EMPTY_SHA256, Request, Scope, canonical_query, signing_key,
    uri_encode,
};
use crate::store::ByteRange;

/// 2013-05-24T00:00:00Z, the S3 examples' time.
const S3_EXAMPLE_TIME: u64 = 1_369_353_600;

fn s3_example_credentials() -> Credentials {
    Credentials::new(
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )
}

fn suite_credentials() -> Credentials {
    Credentials::new("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
}

fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

#[test]
fn dates_format_in_utc() {
    let date = AmzDate::from_unix(1_440_938_160);
    assert_eq!(date.stamp(), "20150830T123600Z");
    assert_eq!(date.date(), "20150830");
    assert_eq!(
        AmzDate::from_unix(S3_EXAMPLE_TIME).stamp(),
        "20130524T000000Z"
    );
    assert_eq!(AmzDate::from_unix(0).stamp(), "19700101T000000Z");
    assert_eq!(AmzDate::from_unix(951_782_400).date(), "20000229");
    assert_eq!(
        AmzDate::from_unix(4_102_444_799).stamp(),
        "20991231T235959Z"
    );
}

#[test]
fn signing_key_matches_the_derivation_example() {
    let key = signing_key(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        &AmzDate::from_unix(1_329_264_000),
        &Scope {
            region: "us-east-1",
            service: "iam",
        },
    );
    assert_eq!(
        hex(&*key),
        "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
    );
}

#[test]
fn suite_get_vanilla() {
    let date = AmzDate::from_unix(1_440_938_160);
    let headers = pairs(&[
        ("Host", "example.amazonaws.com"),
        ("X-Amz-Date", date.stamp()),
    ]);
    let sig = sigv4::sign(
        &suite_credentials(),
        &date,
        &Scope {
            region: "us-east-1",
            service: "service",
        },
        &Request {
            method: "GET",
            path: "/",
            query: &[],
            headers: &headers,
            payload_hash: EMPTY_SHA256,
        },
    );
    assert_eq!(
        sig.authorization,
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
         SignedHeaders=host;x-amz-date, \
         Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    );
}

#[test]
fn suite_get_vanilla_query_order_key_case() {
    let date = AmzDate::from_unix(1_440_938_160);
    let headers = pairs(&[
        ("Host", "example.amazonaws.com"),
        ("X-Amz-Date", date.stamp()),
    ]);
    let query = pairs(&[("Param2", "value2"), ("Param1", "value1")]);
    let sig = sigv4::sign(
        &suite_credentials(),
        &date,
        &Scope {
            region: "us-east-1",
            service: "service",
        },
        &Request {
            method: "GET",
            path: "/",
            query: &query,
            headers: &headers,
            payload_hash: EMPTY_SHA256,
        },
    );
    assert_eq!(
        sig.signature,
        "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
    );
}

#[test]
fn s3_example_get_object_with_range_through_s3_config() {
    let config = S3Config::new(
        "https://s3.amazonaws.com",
        "examplebucket",
        "us-east-1",
        "",
        Addressing::VirtualHost,
        s3_example_credentials(),
    )
    .unwrap();
    let request = config
        .sign_get("test.txt", Some(ByteRange::new(0, 9)), S3_EXAMPLE_TIME)
        .unwrap();
    assert_eq!(
        request.url,
        "https://examplebucket.s3.amazonaws.com/test.txt"
    );
    let auth = &request
        .headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .unwrap()
        .1;
    assert_eq!(
        auth,
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
         SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
         Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
    assert!(request.headers.iter().all(|(k, _)| k != "host"));
}

#[test]
fn s3_example_put_object() {
    let date = AmzDate::from_unix(S3_EXAMPLE_TIME);
    let body_hash = sigv4::sha256_hex(b"Welcome to Amazon S3.");
    assert_eq!(
        body_hash,
        "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
    );
    let headers = pairs(&[
        ("Host", "examplebucket.s3.amazonaws.com"),
        ("Date", "Fri, 24 May 2013 00:00:00 GMT"),
        ("x-amz-date", date.stamp()),
        ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ("x-amz-content-sha256", &body_hash),
    ]);
    let path = format!("/{}", uri_encode("test$file.text", true));
    assert_eq!(path, "/test%24file.text");
    let sig = sigv4::sign(
        &s3_example_credentials(),
        &date,
        &Scope {
            region: "us-east-1",
            service: "s3",
        },
        &Request {
            method: "PUT",
            path: &path,
            query: &[],
            headers: &headers,
            payload_hash: &body_hash,
        },
    );
    assert_eq!(
        sig.signed_headers,
        "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class"
    );
    assert_eq!(
        sig.signature,
        "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
    );
}

#[test]
fn s3_example_list_objects() {
    let date = AmzDate::from_unix(S3_EXAMPLE_TIME);
    let headers = pairs(&[
        ("host", "examplebucket.s3.amazonaws.com"),
        ("x-amz-date", date.stamp()),
        ("x-amz-content-sha256", EMPTY_SHA256),
    ]);
    let query = pairs(&[("prefix", "J"), ("max-keys", "2")]);
    assert_eq!(canonical_query(&query), "max-keys=2&prefix=J");
    let sig = sigv4::sign(
        &s3_example_credentials(),
        &date,
        &Scope {
            region: "us-east-1",
            service: "s3",
        },
        &Request {
            method: "GET",
            path: "/",
            query: &query,
            headers: &headers,
            payload_hash: EMPTY_SHA256,
        },
    );
    assert_eq!(
        sig.signature,
        "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
    );
}

#[test]
fn s3_example_presigned_get_url() {
    let config = S3Config::new(
        "https://s3.amazonaws.com",
        "examplebucket",
        "us-east-1",
        "",
        Addressing::VirtualHost,
        s3_example_credentials(),
    )
    .unwrap();
    let url = config
        .presign_get("test.txt", S3_EXAMPLE_TIME, 86_400)
        .unwrap();
    assert_eq!(
        url,
        "https://examplebucket.s3.amazonaws.com/test.txt\
         ?X-Amz-Algorithm=AWS4-HMAC-SHA256\
         &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
         &X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\
         &X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    );
    assert!(config.presign_get("test.txt", S3_EXAMPLE_TIME, 0).is_err());
    assert!(
        config
            .presign_get("test.txt", S3_EXAMPLE_TIME, 604_801)
            .is_err()
    );
}

#[test]
fn session_tokens_are_signed_and_presigned() {
    let creds = s3_example_credentials().with_session_token("tok/en+=");
    let config = S3Config::new(
        "https://example.r2.cloudflarestorage.com",
        "vault-bucket",
        "auto",
        "deadbolt",
        Addressing::Path,
        creds,
    )
    .unwrap();
    let get = config.sign_get("a/b", None, S3_EXAMPLE_TIME).unwrap();
    assert_eq!(
        get.url,
        "https://example.r2.cloudflarestorage.com/vault-bucket/deadbolt/a/b"
    );
    assert!(
        get.headers
            .contains(&("x-amz-security-token".to_owned(), "tok/en+=".to_owned()))
    );
    let auth = &get
        .headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .unwrap()
        .1;
    assert!(auth.contains("/auto/s3/aws4_request"));
    assert!(auth.contains("x-amz-security-token"));
    let url = config.presign_get("a/b", S3_EXAMPLE_TIME, 60).unwrap();
    assert!(url.contains("X-Amz-Security-Token=tok%2Fen%2B%3D"));
}

#[test]
fn secrets_never_print() {
    let creds = s3_example_credentials().with_session_token("SESSIONSECRET");
    let shown = format!("{creds:?}");
    assert!(!shown.contains("bPxRfiCYEXAMPLEKEY"));
    assert!(!shown.contains("SESSIONSECRET"));
    assert!(shown.contains("AKIAIOSFODNN7EXAMPLE"));
    let config = S3Config::new(
        "https://s3.amazonaws.com",
        "abc",
        "us-east-1",
        "",
        Addressing::Path,
        creds,
    )
    .unwrap();
    assert!(!format!("{config:?}").contains("bPxRfiCYEXAMPLEKEY"));
}

#[test]
fn bad_configs_are_refused() {
    let c = s3_example_credentials;
    assert!(S3Config::new("ftp://x", "abc", "us-east-1", "", Addressing::Path, c()).is_err());
    assert!(
        S3Config::new(
            "https://x/path",
            "abc",
            "us-east-1",
            "",
            Addressing::Path,
            c()
        )
        .is_err()
    );
    assert!(
        S3Config::new(
            "https://u:p@x",
            "abc",
            "us-east-1",
            "",
            Addressing::Path,
            c()
        )
        .is_err()
    );
    assert!(S3Config::new("https://x", "AB", "us-east-1", "", Addressing::Path, c()).is_err());
    assert!(S3Config::new("https://x", "abc", "us east", "", Addressing::Path, c()).is_err());
    assert!(S3Config::new("https://x", "abc", "auto", "../up", Addressing::Path, c()).is_err());
    assert!(S3Config::new("https://x", "abc", "auto", "/ok/", Addressing::Path, c()).is_ok());
    // A password with no user is still a credential in the URL.
    assert!(S3Config::new("https://:p@x", "abc", "auto", "", Addressing::Path, c()).is_err());
    let vhost = |endpoint: &str, bucket: &str| {
        S3Config::new(endpoint, bucket, "auto", "", Addressing::VirtualHost, c())
    };
    assert!(vhost("https://127.0.0.1:9000", "abc").is_err());
    assert!(vhost("http://[::1]:9000", "abc").is_err());
    assert!(vhost("https://s3.example.com", "my.bucket").is_err());
    assert!(vhost("http://s3.example.com", "my.bucket").is_ok());
    assert!(vhost("https://s3.example.com", "my-bucket").is_ok());
}

#[test]
fn whole_keys_stay_within_s3s_limit() {
    let root = "r".repeat(511);
    let config = S3Config::new(
        "https://x.example",
        "abc",
        "auto",
        &root,
        Addressing::Path,
        s3_example_credentials(),
    )
    .unwrap();
    let fits = "n".repeat(512);
    assert!(
        config.sign_put(&fits, b"", true, 0).is_ok(),
        "511 + 1 + 512 = 1024"
    );
    let root = "r".repeat(512);
    let config = S3Config::new(
        "https://x.example",
        "abc",
        "auto",
        &root,
        Addressing::Path,
        s3_example_credentials(),
    )
    .unwrap();
    assert!(matches!(
        config.sign_put(&fits, b"", true, 0),
        Err(crate::RemoteError::Config(_))
    ));
    assert!(config.sign_get(&fits, None, 0).is_err());
    assert!(config.sign_delete(&fits, 0).is_err());
    assert!(config.presign_get(&fits, 0, 60).is_err());
    assert!(
        config
            .sign_list(&format!("{}/", "n".repeat(511)), None, None, 0)
            .is_err()
    );
}
