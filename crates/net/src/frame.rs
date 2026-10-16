//! Length-prefixed frames: `u32 big-endian length || tag (1 byte) || body`.
//! The length covers the tag and the body.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

pub(crate) mod tag {
    pub const HEADS: u8 = 0x01;
    pub const ENTRY: u8 = 0x02;
    pub const DONE: u8 = 0x03;
    pub const RESULT: u8 = 0x04;

    pub const PROOF: u8 = 0x10;
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

pub(crate) async fn read<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<(u8, Vec<u8>)> {
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
    let mut body = vec![0u8; len - 1];
    r.read_exact(&mut body).await?;
    Ok((tag[0], body))
}

pub(crate) async fn expect<R: AsyncRead + Unpin>(
    r: &mut R,
    want: u8,
    max: usize,
) -> Result<Vec<u8>> {
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
    entries: &[Vec<u8>],
) -> Result<()> {
    for entry in entries {
        write(w, tag::ENTRY, entry).await?;
    }
    write(w, tag::DONE, &[]).await
}

pub(crate) async fn read_entries<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<Vec<Vec<u8>>> {
    let mut entries = Vec::new();
    loop {
        match read(r, max).await? {
            (tag::ENTRY, body) => entries.push(body),
            (tag::DONE, _) => return Ok(entries),
            (tag, _) => {
                return Err(Error::Protocol(format!(
                    "expected entry or done, got {tag:#04x}"
                )));
            }
        }
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

    #[tokio::test]
    async fn roundtrip_and_limits() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write(&mut a, tag::HEADS, b"hello").await.unwrap();
        write_entries(&mut a, &[b"x".to_vec(), vec![], b"yz".to_vec()])
            .await
            .unwrap();
        write(&mut a, tag::HEADS, &[0u8; 100]).await.unwrap();
        assert_eq!(expect(&mut b, tag::HEADS, 64).await.unwrap(), b"hello");
        assert_eq!(
            read_entries(&mut b, 64).await.unwrap(),
            vec![b"x".to_vec(), vec![], b"yz".to_vec()]
        );
        assert!(matches!(
            read(&mut b, 64).await,
            Err(Error::FrameTooLarge { len: 101, max: 64 })
        ));
    }
}
