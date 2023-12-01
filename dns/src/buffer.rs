// A specific management for the Vec<u8> type for the FromNetworkOrder trait
use std::convert::AsRef;
use std::fmt;
use std::io::{Cursor, Read};

use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::ToNetwork;

#[derive(Debug, Default, ToNetwork)]
pub struct Buffer(Vec<u8>);

impl Buffer {
    pub fn new(len: u16) -> Self {
        Self(vec![0; len as usize])
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

impl<'a> FromNetworkOrder<'a> for Buffer {
    /// ```
    /// use std::io::Cursor;
    /// use type2network::FromNetworkOrder;
    /// use dns::buffer::Buffer;
    ///
    /// let b = vec![0x12, 0x34, 0x56, 0x78];
    /// let mut buffer = Cursor::new(b.as_slice());
    /// let mut buf = Buffer::new(2);
    /// assert!(buf.deserialize_from(&mut buffer).is_ok());
    /// assert_eq!(buf.as_ref(), &[0x12, 0x34]);
    /// assert!(buf.deserialize_from(&mut buffer).is_ok());
    /// assert_eq!(buf.as_ref(), &[0x56, 0x78]);
    /// ```    
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
        (&self.0).into_iter()
    }
}
