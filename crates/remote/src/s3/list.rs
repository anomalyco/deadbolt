//! `ListObjectsV2` response parsing.

use crate::error::RemoteError;
use crate::xml;

/// One page of a `ListObjectsV2` response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListPage {
    /// Object keys, in the order the store sent them.
    pub keys: Vec<String>,
    /// True if another page follows.
    pub is_truncated: bool,
    /// The token for the next page.
    pub next_continuation_token: Option<String>,
}

/// Parses a `ListBucketResult`. A truncated page without a continuation
/// token is refused, since following it would loop.
pub fn parse_list_objects_v2(body: &str) -> Result<ListPage, RemoteError> {
    let mut page = ListPage::default();
    let mut root_seen = false;
    xml::walk(body, |path, text| {
        match path {
            [root] if root == "ListBucketResult" => root_seen = true,
            [root, contents, key]
                if root == "ListBucketResult" && contents == "Contents" && key == "Key" =>
            {
                page.keys.push(text.to_owned());
            }
            [root, field] if root == "ListBucketResult" && field == "IsTruncated" => {
                page.is_truncated = match text {
                    "true" => true,
                    "false" => false,
                    _ => return Err(RemoteError::Protocol("IsTruncated is not a boolean".into())),
                };
            }
            [root, field] if root == "ListBucketResult" && field == "NextContinuationToken" => {
                page.next_continuation_token = Some(text.to_owned()).filter(|t| !t.is_empty());
            }
            [root, ..] if root == "Error" => {
                return Err(RemoteError::Protocol("store returned an S3 <Error>".into()));
            }
            _ => {}
        }
        Ok(())
    })?;
    if !root_seen {
        return Err(RemoteError::Protocol("not a ListBucketResult".into()));
    }
    if page.is_truncated && page.next_continuation_token.is_none() {
        return Err(RemoteError::Protocol(
            "truncated listing without NextContinuationToken".into(),
        ));
    }
    Ok(page)
}
