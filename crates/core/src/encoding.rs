use zeroize::Zeroizing;

use crate::error::DecodeError;

/// Where a [`Writer`] puts bytes.
pub(crate) trait Sink {
    fn put(&mut self, bytes: &[u8]);
}

impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// Plaintext output, wiped on drop. Callers pre-size it with [`Count`] so it
/// never reallocates and leaves an unwiped copy behind.
impl Sink for Zeroizing<Vec<u8>> {
    fn put(&mut self, bytes: &[u8]) {
        debug_assert!(
            self.capacity() - self.len() >= bytes.len(),
            "pre-size the buffer"
        );
        self.extend_from_slice(bytes);
    }
}

/// Counts the bytes an encoding would take without writing them.
#[derive(Default)]
pub(crate) struct Count(pub(crate) usize);

impl Sink for Count {
    fn put(&mut self, bytes: &[u8]) {
        self.0 += bytes.len();
    }
}

pub(crate) struct Writer<S>(S);

impl<S: Sink> Writer<S> {
    pub(crate) fn new(sink: S) -> Self {
        Self(sink)
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.0.put(&[v]);
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.0.put(&v.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.0.put(&v.to_be_bytes());
    }

    #[expect(
        clippy::expect_used,
        reason = "wire lengths are u32; encoding larger in-memory values is a programmer error"
    )]
    pub(crate) fn len(&mut self, len: usize) {
        self.u32(u32::try_from(len).expect("length exceeds u32::MAX"));
    }

    pub(crate) fn bytes(&mut self, v: &[u8]) {
        self.0.put(v);
    }

    pub(crate) fn str(&mut self, v: &str) {
        self.len(v.len());
        self.bytes(v.as_bytes());
    }

    pub(crate) fn finish(self) -> S {
        self.0
    }
}

/// A writer over any sink, so one encoding function serves counting and writing.
pub(crate) type DynWriter<'a> = Writer<&'a mut dyn Sink>;

/// The length of what `write` encodes.
pub(crate) fn encoded_len(write: impl Fn(&mut DynWriter<'_>)) -> usize {
    let mut count = Count::default();
    write(&mut Writer::new(&mut count as &mut dyn Sink));
    count.0
}

/// Encodes with `write` into an exactly sized buffer that is wiped on drop.
pub(crate) fn zeroizing(write: impl Fn(&mut DynWriter<'_>)) -> Zeroizing<Vec<u8>> {
    let len = encoded_len(&write);
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    write(&mut Writer::new(&mut out as &mut dyn Sink));
    debug_assert_eq!(out.len(), len);
    out
}

impl<S: Sink + ?Sized> Sink for &mut S {
    fn put(&mut self, bytes: &[u8]) {
        (**self).put(bytes);
    }
}

pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.0.len() < n {
            return Err(DecodeError::UnexpectedEnd);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut bytes = [0; N];
        bytes.copy_from_slice(self.take(N)?);
        Ok(bytes)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn string(&mut self) -> Result<String, DecodeError> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        Ok(std::str::from_utf8(bytes)
            .map_err(|_| DecodeError::InvalidUtf8)?
            .to_owned())
    }

    pub(crate) fn finish(self) -> Result<(), DecodeError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}
