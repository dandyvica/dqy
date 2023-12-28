// A specific management for the Vec<u8> type for the FromNetworkOrder trait
use std::convert::AsRef;
use std::fmt;
use std::io::Cursor;

use type2network::FromNetworkOrder;

#[derive(Debug, Default)]
pub struct BufferMut<'a> {
    length: usize,
    data: &'a [u8],
}

impl<'a> BufferMut<'a> {
    pub fn new<T: Into<usize>>(len: T) -> Self {
        Self {
            length: len.into(),
            data: &[],
        }
    }

    // when printing out some RRs, it's easier to use this
    pub fn to_string(&self) -> String {
        String::from_utf8_lossy(&self.data).to_string()
    }
}

impl<'a> fmt::Display for BufferMut<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.data {
            write!(f, "{:X?}", c)?;
        }
        Ok(())
    }
}

// no ToNetworkOrder: we'll use this buffer only for deserialization
impl<'a> FromNetworkOrder<'a> for BufferMut<'a> {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        let pos = buffer.position();
        self.data = &buffer.get_ref()[pos as usize..pos as usize + self.length as usize];
        buffer.set_position(pos + self.length as u64);
        Ok(())
    }
}

// AsRef to benefit from already defined methods on Vec
impl<'a> AsRef<[u8]> for BufferMut<'a> {
    fn as_ref(&self) -> &[u8] {
        self.data
    }
}

// IntoIterator to benefit from already defined iterator on Vec
impl<'a> IntoIterator for &'a BufferMut<'a> {
    type Item = &'a u8;
    type IntoIter = std::slice::Iter<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        (&self.data).into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use type2network::FromNetworkOrder;

    #[test]
    fn network() {
        // from
        let x = [0x12u8, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let mut c = std::io::Cursor::new(&x[..]);

        let mut buf = BufferMut::new(2u16);
        buf.deserialize_from(&mut c).unwrap();
        assert_eq!(buf.data, &[0x12, 0x34]);

        let mut buf = BufferMut::new(2u16);
        buf.deserialize_from(&mut c).unwrap();
        assert_eq!(buf.data, &[0x56, 0x78]);

        let mut buf = BufferMut::new(2u16);
        buf.deserialize_from(&mut c).unwrap();
        assert_eq!(buf.data, &[0x9A, 0xBC]);
    }
}
