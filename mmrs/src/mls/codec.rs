pub struct TlsReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> TlsReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }

    /// The bytes read since `start`.
    pub fn since(&self, start: usize) -> &'a [u8] {
        &self.buf[start..self.pos]
    }

    pub fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let bytes = self.buf.get(self.pos..self.pos.checked_add(len)?)?;
        self.pos += len;
        Some(bytes)
    }

    pub fn u8(&mut self) -> Option<u8> {
        Some(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.bytes(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.bytes(8)?.try_into().unwrap()))
    }

    /// `opaque data<V>`: a varint length, then that many bytes.
    pub fn vector(&mut self) -> Option<&'a [u8]> {
        let first = *self.buf.get(self.pos)?;
        let len = match first >> 6 {
            0 => usize::from(self.u8()?),
            1 => usize::from(self.u16()? & 0x3fff),
            2 => (self.u32()? & 0x3fff_ffff) as usize,
            _ => return None,
        };
        self.bytes(len)
    }

    /// `T items<V>`, read with `item` until the vector is used up.
    pub fn items<T>(&mut self, mut item: impl FnMut(&mut Self) -> Option<T>) -> Option<Vec<T>> {
        let mut inner = TlsReader::new(self.vector()?);
        let mut items = Vec::new();
        while !inner.is_empty() {
            items.push(item(&mut inner)?);
        }
        Some(items)
    }
}

#[derive(Default)]
pub struct TlsWriter {
    buf: Vec<u8>,
}

impl TlsWriter {
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.bytes(&[value])
    }

    pub fn u16(&mut self, value: u16) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    pub fn vector(&mut self, bytes: &[u8]) -> &mut Self {
        let len = bytes.len();
        match len {
            0..0x40 => self.u8(len as u8),
            0x40..0x4000 => self.u16(0x4000 | len as u16),
            0x4000..0x4000_0000 => self.u32(0x8000_0000 | len as u32),
            _ => panic!("MLS vectors are limited to 2^30 bytes"),
        };
        self.bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_vectors_round_trip() {
        for len in [0, 63, 64, 16383, 16384] {
            let data = vec![7; len];
            let mut writer = TlsWriter::default();
            writer.vector(&data).u8(1);
            let bytes = writer.into_bytes();

            let mut reader = TlsReader::new(&bytes);
            assert_eq!(reader.vector().unwrap(), data);
            assert_eq!(reader.u8(), Some(1));
            assert!(reader.is_empty());
        }
    }

    #[test]
    fn rejects_truncated_and_reserved_lengths() {
        assert!(TlsReader::new(&[0x05, 1, 2]).vector().is_none());
        assert!(TlsReader::new(&[0xc0, 0]).vector().is_none());
    }
}
