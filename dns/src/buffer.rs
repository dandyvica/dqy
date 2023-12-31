// A specific management for the Vec<u8> type for the FromNetworkOrder trait
use std::convert::AsRef;
use std::fmt;
use std::io::{Cursor, Read};
use std::ops::Deref;

use type2network::{FromNetworkOrder, ToNetworkOrder};

#[derive(Debug, Default)]
pub struct Buffer(Vec<u8>);

impl Buffer {
    pub fn new<T: Into<usize>>(len: T) -> Self {
        Self(vec![0; len.into()])
    }

    // when printing out some RRs, it's easier to use this
    pub fn to_string(&self) -> String {
        String::from_utf8_lossy(&self.0).to_string()
    }
}

impl Deref for Buffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in &self.0 {
            write!(f, "{:X?}", c)?;
        }
        Ok(())
    }
}

// a more efficient serialize_to() for Vec<u8>
impl ToNetworkOrder for Buffer {
    fn serialize_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<usize> {
        let length = self.0.len();
        buffer.extend(self);

        Ok(length)
    }
}

impl<'a> FromNetworkOrder<'a> for Buffer {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        buffer.read_exact(self.0.as_mut_slice())?;
        Ok(())
    }
}

// AsRef to benefit from already defined methods on Vec
impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// IntoIterator to benefit from already defined iterator on Vec
impl<'a> IntoIterator for &'a Buffer {
    type Item = &'a u8;
    type IntoIter = std::slice::Iter<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::to_network_test;
    use std::io::Cursor;
    use type2network::FromNetworkOrder;

    #[test]
    fn network() {
        // to
        let mut buf = Buffer::new(3u16);
        buf.0 = vec![0, 1, 2];
        to_network_test(&buf, 3, &[0, 1, 2]);

        let b = vec![0x12, 0x34, 0x56, 0x78];
        let mut buffer = Cursor::new(b.as_slice());
        let mut buf = Buffer::new(2u16);
        assert!(buf.deserialize_from(&mut buffer).is_ok());
        assert_eq!(buf.as_ref(), &[0x12, 0x34]);
        assert!(buf.deserialize_from(&mut buffer).is_ok());
        assert_eq!(buf.as_ref(), &[0x56, 0x78]);
    }
}
