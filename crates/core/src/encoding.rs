use crate::error::DecodeError;

#[derive(Default)]
pub(crate) struct Writer(Vec<u8>);

impl Writer {
    pub(crate) fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn len(&mut self, len: usize) {
        self.u32(u32::try_from(len).expect("length exceeds u32::MAX"));
    }

    pub(crate) fn bytes(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }

    pub(crate) fn str(&mut self, v: &str) {
        self.len(v.len());
        self.bytes(v.as_bytes());
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
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
        Ok(self.take(N)?.try_into().expect("take returned N bytes"))
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
        String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::InvalidUtf8)
    }

    pub(crate) fn finish(self) -> Result<(), DecodeError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}
