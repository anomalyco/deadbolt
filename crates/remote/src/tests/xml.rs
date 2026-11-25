//! S3 `ListObjectsV2` and WebDAV `PROPFIND` parsing against replies shaped
//! like real servers'.

use crate::RemoteError;
use crate::s3::parse_list_objects_v2;
use crate::webdav::{DavAuth, DavEntry, WebDavConfig, parent_dirs, parse_multistatus};

#[test]
fn s3_list_page_with_continuation_and_entities() {
    let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name><Prefix>v/</Prefix><KeyCount>2</KeyCount><MaxKeys>2</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken>
  <Contents><Key>v/a&amp;b</Key><LastModified>2026-11-24T00:00:00.000Z</LastModified>
    <ETag>&quot;9b2cf535f27731c974343645a3985328&quot;</ETag><Size>3</Size><StorageClass>STANDARD</StorageClass></Contents>
  <Contents><Key><![CDATA[v/c]]></Key><Size>0</Size></Contents>
  <Contents><Key>v/&#x64;</Key></Contents>
</ListBucketResult>"#;
    let page = parse_list_objects_v2(body).unwrap();
    assert_eq!(page.keys, ["v/a&b", "v/c", "v/d"]);
    assert!(page.is_truncated);
    assert_eq!(
        page.next_continuation_token.as_deref(),
        Some("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=")
    );
}

#[test]
fn s3_list_last_page_r2_and_minio_shapes() {
    // R2 omits the namespace and sends an empty token element.
    let r2 = "<ListBucketResult><IsTruncated>false</IsTruncated><NextContinuationToken></NextContinuationToken>\
              <Contents><Key>k</Key></Contents></ListBucketResult>";
    let page = parse_list_objects_v2(r2).unwrap();
    assert_eq!(page.keys, ["k"]);
    assert!(!page.is_truncated);
    assert_eq!(page.next_continuation_token, None);
    // MinIO, an empty bucket.
    let minio = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix></Prefix>
<KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><Delimiter></Delimiter><IsTruncated>false</IsTruncated></ListBucketResult>"#;
    assert!(parse_list_objects_v2(minio).unwrap().keys.is_empty());
}

#[test]
fn s3_list_refuses_errors_loops_and_garbage() {
    let error = "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>";
    assert!(parse_list_objects_v2(error).is_err());
    let loop_page = "<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>";
    assert!(parse_list_objects_v2(loop_page).is_err());
    assert!(
        parse_list_objects_v2(
            "<ListBucketResult><IsTruncated>yes</IsTruncated></ListBucketResult>"
        )
        .is_err()
    );
    assert!(parse_list_objects_v2("<ListBucketResult><Contents><Key>x</Key>").is_err());
    assert!(
        parse_list_objects_v2(
            "<ListBucketResult><Contents><Key>&xxe;</Key></Contents></ListBucketResult>"
        )
        .is_err()
    );
    assert!(parse_list_objects_v2("<html>nope</html>").is_err());
}

fn entry(href: &str, is_collection: bool) -> DavEntry {
    DavEntry {
        hrefs: vec![href.to_owned()],
        is_collection,
    }
}

const NEXTCLOUD: &str = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
 <d:response>
  <d:href>/remote.php/dav/files/alex%40example.com/deadbolt/</d:href>
  <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
 </d:response>
 <d:response>
  <d:href>/remote.php/dav/files/alex%40example.com/deadbolt/v1/</d:href>
  <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
 </d:response>
 <d:response>
  <d:href>/remote.php/dav/files/alex%40example.com/deadbolt/file-1</d:href>
  <d:propstat><d:prop><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  <d:propstat><d:prop><d:getetag/></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>
 </d:response>
</d:multistatus>"#;

#[test]
fn nextcloud_multistatus() {
    let entries = parse_multistatus(NEXTCLOUD).unwrap();
    assert_eq!(
        entries,
        [
            entry("/remote.php/dav/files/alex%40example.com/deadbolt/", true),
            entry(
                "/remote.php/dav/files/alex%40example.com/deadbolt/v1/",
                true
            ),
            entry(
                "/remote.php/dav/files/alex%40example.com/deadbolt/file-1",
                false
            ),
        ]
    );
    let config = WebDavConfig::new(
        "https://cloud.example.com/remote.php/dav/files/alex@example.com/deadbolt",
        DavAuth::None,
    )
    .unwrap();
    let names: Vec<Option<String>> = entries
        .iter()
        .map(|e| config.name_of_href(&e.hrefs[0]))
        .collect();
    assert_eq!(
        names,
        [
            Some(String::new()),
            Some("v1/".to_owned()),
            Some("file-1".to_owned())
        ]
    );
}

#[test]
fn fastmail_absolute_hrefs_with_uppercase_prefix() {
    let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response><D:href>https://myfiles.fastmail.com/deadbolt/</D:href>
<D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
<D:response><D:href>https://myfiles.fastmail.com/deadbolt/abc/0000000000000001</D:href>
<D:propstat><D:prop><D:resourcetype/></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
<D:response><D:href>https://evil.example/deadbolt/abc/0000000000000002</D:href>
<D:propstat><D:prop><D:resourcetype/></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
</D:multistatus>"#;
    let entries = parse_multistatus(body).unwrap();
    assert_eq!(entries.len(), 3);
    let config =
        WebDavConfig::new("https://myfiles.fastmail.com/deadbolt/", DavAuth::None).unwrap();
    assert_eq!(
        config.name_of_href(&entries[1].hrefs[0]).as_deref(),
        Some("abc/0000000000000001")
    );
    assert_eq!(
        config.name_of_href(&entries[2].hrefs[0]),
        None,
        "other host"
    );
}

#[test]
fn sabredav_apache_and_nginx_namespace_styles() {
    // Apache mod_dav: live properties under another prefix bound to DAV:.
    let apache = r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:ns0="DAV:">
<D:response xmlns:lp1="DAV:"><D:href>/dav/a/</D:href>
<D:propstat><D:prop><lp1:resourcetype><D:collection/></lp1:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
<D:response xmlns:lp1="DAV:"><D:href>/dav/a/b%2dc</D:href>
<D:propstat><D:prop><lp1:resourcetype/></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
</D:multistatus>"#;
    assert_eq!(
        parse_multistatus(apache).unwrap(),
        [entry("/dav/a/", true), entry("/dav/a/b%2dc", false)]
    );
    // A default namespace and no prefix at all (SabreDAV can be set up so).
    let plain = r#"<multistatus xmlns="DAV:"><response><href>/dav/x</href>
<propstat><prop><resourcetype></resourcetype></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>"#;
    assert_eq!(parse_multistatus(plain).unwrap(), [entry("/dav/x", false)]);
    // nginx-dav-ext: collections only marked by the trailing slash.
    let nginx = r#"<?xml version="1.0" encoding="utf-8" ?><D:multistatus xmlns:D="DAV:">
<D:response><D:href>/dav/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop>
<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
<D:response><D:href>/dav/sub/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop>
<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"#;
    let config = WebDavConfig::new("http://127.0.0.1:8080/dav", DavAuth::None).unwrap();
    let names: Vec<_> = parse_multistatus(nginx)
        .unwrap()
        .iter()
        .map(|e| config.name_of_href(&e.hrefs[0]))
        .collect();
    assert_eq!(names, [Some(String::new()), Some("sub/".to_owned())]);
    assert_eq!(
        config.name_of_href("/dav/a/b%2dc").as_deref(),
        Some("a/b-c")
    );
}

#[test]
fn hrefs_outside_the_base_or_not_names_are_dropped() {
    let config = WebDavConfig::new("https://h.example/base/", DavAuth::None).unwrap();
    assert_eq!(config.name_of_href("/other/x"), None);
    assert_eq!(config.name_of_href("/base/../etc/passwd"), None);
    assert_eq!(config.name_of_href("/base/UPPER"), None);
    assert_eq!(config.name_of_href("/base/a%00b"), None);
    assert_eq!(config.name_of_href("/base/%zz"), None);
    assert_eq!(config.name_of_href("relative"), None);
    assert_eq!(config.name_of_href("/base").as_deref(), Some(""));
}

#[test]
fn webdav_parser_refuses_malformed_replies() {
    assert!(
        parse_multistatus(
            "<d:multistatus xmlns:d=\"DAV:\"><d:response></d:response></d:multistatus>"
        )
        .is_err()
    );
    assert!(parse_multistatus("<html/>").is_err());
    assert!(parse_multistatus("<d:multistatus xmlns:d=\"DAV:\"><d:response>").is_err());
}

#[test]
fn webdav_config_and_secrets() {
    let auth = DavAuth::Basic {
        user: "alex".into(),
        password: "hunter2-app-password".to_owned().into(),
    };
    let config = WebDavConfig::new("https://h.example/dav", auth).unwrap();
    assert_eq!(config.url("a/b"), "https://h.example/dav/a/b");
    assert!(!format!("{config:?}").contains("hunter2"));
    assert!(
        !format!("{:?}", DavAuth::Bearer("tok-secret".to_owned().into())).contains("tok-secret")
    );
    assert!(WebDavConfig::new("https://u:p@h.example/dav", DavAuth::None).is_err());
    assert!(WebDavConfig::new("ftp://h.example/dav", DavAuth::None).is_err());
    assert_eq!(parent_dirs("a/b/c"), ["a/", "a/b/"]);
    assert!(parent_dirs("a").is_empty());
}

#[test]
fn s3_list_keeps_token_whitespace_and_decodes_url_encoded_keys() {
    let body = "<ListBucketResult><EncodingType>url</EncodingType>\
                <IsTruncated>\n  true\n</IsTruncated>\
                <NextContinuationToken> tok/en= </NextContinuationToken>\
                <Contents><Key>v%2Fd%2Fa%25b</Key></Contents>\
                <Contents><Key>v/d/c</Key></Contents></ListBucketResult>";
    let page = parse_list_objects_v2(body).unwrap();
    assert_eq!(page.keys, ["v/d/a%b", "v/d/c"]);
    assert!(page.is_truncated);
    assert_eq!(
        page.next_continuation_token.as_deref(),
        Some(" tok/en= "),
        "a token is opaque: never trimmed or decoded"
    );
    // Without EncodingType the keys are raw.
    let raw = "<ListBucketResult><IsTruncated>false</IsTruncated>\
               <Contents><Key>v%2Fd</Key></Contents></ListBucketResult>";
    assert_eq!(parse_list_objects_v2(raw).unwrap().keys, ["v%2Fd"]);
    let bad = "<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated>\
               <Contents><Key>v%zz</Key></Contents></ListBucketResult>";
    assert!(parse_list_objects_v2(bad).is_err());
}

const STATUSES: &str = r#"<d:multistatus xmlns:d="DAV:">
<d:response><d:href>/dav/</d:href>
 <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
<d:response><d:href>/dav/gone/</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response>
<d:response><d:href>/dav/a</d:href><d:href>/dav/b</d:href><d:status>HTTP/1.1 200 OK</d:status></d:response>
<d:response><d:href>/dav/notdir</d:href>
 <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>
 <d:propstat><d:prop><d:getetag>x</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
</d:multistatus>"#;

#[test]
fn multistatus_honours_response_and_propstat_status() {
    let entries = parse_multistatus(STATUSES).unwrap();
    assert_eq!(
        entries,
        [
            entry("/dav/", true),
            DavEntry {
                hrefs: vec!["/dav/a".to_owned(), "/dav/b".to_owned()],
                is_collection: false,
            },
            entry("/dav/notdir", false),
        ],
        "404 response skipped, both hrefs kept, collection only from a 2xx propstat"
    );
    for (status, code) in [
        ("403 Forbidden", 403),
        ("401 Unauthorized", 401),
        ("503 Busy", 503),
    ] {
        let body = format!(
            r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/x</d:href>
<d:status>HTTP/1.1 {status}</d:status></d:response></d:multistatus>"#
        );
        assert!(
            matches!(
                parse_multistatus(&body),
                Err(RemoteError::Status { status, .. }) if status == code
            ),
            "{status}"
        );
    }
    let garbled = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/x</d:href>
<d:status>nonsense</d:status></d:response></d:multistatus>"#;
    assert!(parse_multistatus(garbled).is_err());
}

#[test]
fn href_schemes_ports_and_slashes() {
    let config = WebDavConfig::new("https://h.example/base/", DavAuth::None).unwrap();
    assert_eq!(
        config.name_of_href("HTTPS://H.example/base/x").as_deref(),
        Some("x")
    );
    assert_eq!(
        config
            .name_of_href("https://h.example:443/base/x")
            .as_deref(),
        Some("x")
    );
    assert_eq!(config.name_of_href("https://h.example:8443/base/x"), None);
    assert_eq!(config.name_of_href("http://h.example/base/x"), None);
    assert_eq!(config.name_of_href("/base/a/").as_deref(), Some("a/"));
    assert_eq!(config.name_of_href("/base/a//"), None);
    assert_eq!(config.name_of_href("/base/a///"), None);
    assert_eq!(config.name_of_href(" /base/x\n").as_deref(), Some("x"));
}
