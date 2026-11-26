//! Talking to the daemon: its control protocol, where its files live,
//! starting it on demand, replacing a daemon of an older protocol, and sending
//! requests. The CLI and the desktop app are both clients of this crate.
//!
//! With `default-features = false` (used by `deadbolt-ffi` for macOS
//! AutoFill), only [`peer`], [`append`], and [`encode_json`] are compiled —
//! no `tokio`, `zip`, `flate2`, `tempfile`, or OTLP telemetry.

#[cfg(feature = "host")]
mod daemon;
#[cfg(feature = "host")]
pub mod export;
#[cfg(feature = "host")]
pub mod file;
#[cfg(feature = "host")]
pub mod paths;
pub mod peer;
#[cfg(feature = "host")]
pub mod telemetry;

#[cfg(feature = "host")]
pub use daemon::*;
#[cfg(feature = "host")]
pub use paths::Paths;

use zeroize::Zeroizing;

/// Appends `bytes` to a buffer of secrets. It grows by copying into a new
/// buffer (to at most `max`, unless `bytes` need more) and wiping the old
/// one, so no reallocation leaves a copy behind.
pub fn append(buffer: &mut Zeroizing<Vec<u8>>, bytes: &[u8], max: usize) {
    if buffer.capacity() - buffer.len() < bytes.len() {
        let needed = buffer.len() + bytes.len();
        let capacity = (buffer.capacity() * 2).min(max).max(needed);
        let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
        grown.extend_from_slice(buffer);
        *buffer = grown;
    }
    buffer.extend_from_slice(bytes);
}

/// `value` as JSON between `before` and `after`, for messages that can
/// carry secrets: the buffer is sized up front, so no reallocation leaves a
/// copy behind, and wiped on drop.
pub fn encode_json(
    before: &[u8],
    value: &impl serde::Serialize,
    after: &[u8],
) -> serde_json::Result<Zeroizing<Vec<u8>>> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut len = Count(0);
    serde_json::to_writer(&mut len, value)?;
    let mut body = Zeroizing::new(Vec::with_capacity(before.len() + len.0 + after.len()));
    body.extend_from_slice(before);
    serde_json::to_writer(&mut *body, value)?;
    body.extend_from_slice(after);
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encoding never reallocates, which would leave a copy of a secret in
    /// freed memory.
    #[test]
    fn encoded_messages_fit_their_buffers_exactly() {
        let secret = "s".repeat(1000);
        for (before, after) in [
            (
                &b""[..],
                &b"
"[..],
            ),
            (&[7, 0, 0, 0][..], &b""[..]),
        ] {
            let body =
                encode_json(before, &serde_json::json!({"password": secret}), after).unwrap();
            assert_eq!(body.capacity(), body.len());
            assert!(body.starts_with(before) && body.ends_with(after));
            assert_eq!(body.len(), before.len() + 1015 + after.len());
        }
    }

    #[test]
    fn append_grows_within_cap() {
        let mut buf = Zeroizing::new(Vec::with_capacity(4));
        append(&mut buf, b"abcd", 16);
        assert_eq!(&*buf, b"abcd");
        append(&mut buf, b"efgh", 16);
        assert_eq!(&*buf, b"abcdefgh");
        assert!(buf.capacity() <= 16);
    }
}
