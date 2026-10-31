//! Length-prefixed frames: `u32 big-endian length || tag (1 byte) || body`.
//! The length covers the tag and the body.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::{Blob, DEFAULT_MAX_FRAME_LEN};

pub(crate) mod tag {
    pub const HEADS: u8 = 0x01;
    pub const ENTRY: u8 = 0x02;
    pub const DONE: u8 = 0x03;
    pub const RESULT: u8 = 0x04;

    pub const PAKE: u8 = 0x10;
    pub const CONFIRM: u8 = 0x11;
    pub const OFFER: u8 = 0x12;
    pub const JOIN: u8 = 0x13;
}

pub(crate) async fn write<W: AsyncWrite + Unpin>(w: &mut W, tag: u8, body: &[u8]) -> Result<()> {
    let len = u32::try_from(body.len() + 1).map_err(|_| Error::FrameTooLarge {
        len: body.len() + 1,
        max: u32::MAX as usize,
    })?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&[tag]).await?;
    w.write_all(body).await?;
    Ok(())
}

/// Reads one frame. The body may be an entry holding secret values, so it is read
/// into an exactly sized buffer that is wiped on drop.
pub(crate) async fn read<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<(u8, Blob)> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 {
        return Err(Error::Protocol("empty frame".into()));
    }
    if len > max {
        return Err(Error::FrameTooLarge { len, max });
    }
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag).await?;
    let mut body = Zeroizing::new(vec![0u8; len - 1]);
    r.read_exact(&mut body).await?;
    Ok((tag[0], body))
}

pub(crate) async fn expect<R: AsyncRead + Unpin>(r: &mut R, want: u8, max: usize) -> Result<Blob> {
    let (tag, body) = read(r, max).await?;
    if tag != want {
        return Err(Error::Protocol(format!(
            "expected frame {want:#04x}, got {tag:#04x}"
        )));
    }
    Ok(body)
}

pub(crate) async fn write_entries<W: AsyncWrite + Unpin>(
    w: &mut W,
    entries: impl Iterator<Item = Result<Blob, crate::HandlerError>>,
) -> Result<usize> {
    let mut count = 0;
    for entry in entries {
        let entry = entry.map_err(Error::Handler)?;
        write(w, tag::ENTRY, &entry).await?;
        count += 1;
    }
    write(w, tag::DONE, &[]).await?;
    Ok(count)
}

/// Most entry bytes [`read_batch`] buffers: two maximum-size frames. A batch stops
/// growing once it reaches this, so it holds at most this plus one frame.
pub(crate) const BATCH_BYTES: usize = 2 * DEFAULT_MAX_FRAME_LEN;
/// Most entries [`read_batch`] buffers, bounding per-entry overhead when entries are
/// tiny. A real vault's history is tens of thousands of entries at most, so a
/// session rarely needs more than one batch.
pub(crate) const BATCH_ENTRIES: usize = 64 * 1024;

/// Reads `ENTRY` frames until `DONE` or until the batch holds [`BATCH_ENTRIES`]
/// entries or [`BATCH_BYTES`] bytes. Returns the batch and whether `DONE` was read.
pub(crate) async fn read_batch<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<(Vec<Blob>, bool)> {
    let mut entries = Vec::new();
    let mut bytes = 0;
    while entries.len() < BATCH_ENTRIES && bytes < BATCH_BYTES {
        match read_entry(r, max).await? {
            Some(body) => {
                bytes += body.len();
                entries.push(body);
            }
            None => return Ok((entries, true)),
        }
    }
    Ok((entries, false))
}

pub(crate) async fn read_entry<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<Option<Blob>> {
    match read(r, max).await? {
        (tag::ENTRY, body) => Ok(Some(body)),
        (tag::DONE, _) => Ok(None),
        (tag, _) => Err(Error::Protocol(format!(
            "expected entry or done, got {tag:#04x}"
        ))),
    }
}

/// `RESULT` body: empty on success, otherwise a UTF-8 error message.
pub(crate) async fn write_result<W: AsyncWrite + Unpin>(
    w: &mut W,
    result: &std::result::Result<(), String>,
) -> Result<()> {
    match result {
        Ok(()) => write(w, tag::RESULT, &[]).await,
        Err(msg) => {
            let msg = if msg.is_empty() {
                "error"
            } else {
                msg.as_str()
            };
            write(w, tag::RESULT, msg.as_bytes()).await
        }
    }
}

pub(crate) async fn read_result<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<()> {
    let body = expect(r, tag::RESULT, max).await?;
    if body.is_empty() {
        Ok(())
    } else {
        Err(Error::Remote(String::from_utf8_lossy(&body).into_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blobs(items: &[&[u8]]) -> Vec<Blob> {
        items.iter().map(|b| Zeroizing::new(b.to_vec())).collect()
    }

    #[tokio::test]
    async fn roundtrip_and_limits() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write(&mut a, tag::HEADS, b"hello").await.unwrap();
        write_entries(&mut a, blobs(&[b"x", b"", b"yz"]).into_iter().map(Ok))
            .await
            .unwrap();
        write(&mut a, tag::HEADS, &[0u8; 100]).await.unwrap();
        assert_eq!(*expect(&mut b, tag::HEADS, 64).await.unwrap(), b"hello");
        assert_eq!(
            read_batch(&mut b, 64).await.unwrap(),
            (blobs(&[b"x", b"", b"yz"]), true)
        );
        assert!(matches!(
            read(&mut b, 64).await,
            Err(Error::FrameTooLarge { len: 101, max: 64 })
        ));
    }

    /// Many tiny entries come in batches of at most `BATCH_ENTRIES`, in order.
    #[tokio::test]
    async fn batches_bound_entry_count() {
        let count = 2 * BATCH_ENTRIES + 3;
        let entries: Vec<Blob> = (0..count)
            .map(|i| Zeroizing::new((i as u32).to_be_bytes().to_vec()))
            .collect();
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let write = write_entries(&mut a, entries.iter().cloned().map(Ok));
        let read = async {
            let mut sizes = Vec::new();
            let mut all = Vec::new();
            loop {
                let (mut batch, done) = read_batch(&mut b, 64).await.unwrap();
                sizes.push(batch.len());
                all.append(&mut batch);
                if done {
                    return (sizes, all);
                }
            }
        };
        let (written, (sizes, all)) = tokio::join!(write, read);
        written.unwrap();
        assert_eq!(sizes, vec![BATCH_ENTRIES, BATCH_ENTRIES, 3]);
        assert_eq!(all, entries);
    }

    /// Large entries come in batches of about `BATCH_BYTES`, and one entry larger than
    /// that still gets through on its own.
    #[tokio::test]
    async fn batches_bound_bytes() {
        let max = BATCH_BYTES + 2;
        let entries: Vec<Blob> = [BATCH_BYTES / 2, BATCH_BYTES / 2, BATCH_BYTES + 1, 7]
            .into_iter()
            .map(|len| Zeroizing::new(vec![1; len]))
            .collect();
        let (mut a, mut b) = tokio::io::duplex(1024 * 1024);
        let write = write_entries(&mut a, entries.iter().cloned().map(Ok));
        let read = async {
            let mut sizes = Vec::new();
            loop {
                let (batch, done) = read_batch(&mut b, max).await.unwrap();
                sizes.push(batch.iter().map(|e| e.len()).collect::<Vec<_>>());
                if done {
                    return sizes;
                }
            }
        };
        let (written, sizes) = tokio::join!(write, read);
        written.unwrap();
        assert_eq!(
            sizes,
            vec![
                vec![BATCH_BYTES / 2, BATCH_BYTES / 2],
                vec![BATCH_BYTES + 1],
                vec![7],
            ]
        );
    }
}
