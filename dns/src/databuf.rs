// A specific management for the Vec<u8> type for the FromNetworkOrder trait
use std::convert::AsRef;
use std::fmt;
use std::io::{Cursor, Read};
use std::ops::Deref;
use std::slice::Iter;

use type2network::{FromNetworkOrder, ToNetworkOrder};

/// A generic buffer which is used for reading or writing data.
#[derive(Default)]
pub struct DataBuf<T> {
    length: usize,
    data: T,
}

impl<T> DataBuf<T> {
    pub fn with_capacity<L: Into<usize>>(capa: L) -> Self
    where
        T: Default,
    {
        Self {
            length: capa.into(),
            data: T::default(),
        }
    }

    pub fn iter<'a>(&'a self) -> Iter<'a, u8>
    where
        T: AsRef<[u8]>,
    {
        self.data.as_ref().iter()
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Deref for DataBuf<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> fmt::Debug for DataBuf<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.iter() {
            write!(f, "{:X?}", c)?;
        }
        Ok(())
    }
}

impl<T> fmt::Display for DataBuf<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = String::from_utf8_lossy(&self.data.as_ref()).to_string();
        write!(f, "{}", s)
    }
}

// AsRef to benefit from already defined methods on Vec
impl<T> AsRef<[u8]> for DataBuf<T>
where
    T: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        &self.data.as_ref()
    }
}

// These are the 2 aliases used
pub type Buffer = DataBuf<Vec<u8>>;
pub type BufferMut<'a> = DataBuf<&'a [u8]>;

// a more efficient serialize_to() for Vec<u8>
impl ToNetworkOrder for Buffer {
    fn serialize_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<usize> {
        let length = self.len();
        buffer.extend(&self.data);

        Ok(length)
    }
}

impl<'a> FromNetworkOrder<'a> for Buffer {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        buffer.read_exact(self.data.as_mut_slice())?;
        Ok(())
    }
}

// no ToNetworkOrder: we'll use this buffer only for deserialization
impl<'a> FromNetworkOrder<'a> for BufferMut<'a> {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        let pos = buffer.position();
        self.data = &buffer.get_ref()[pos as usize..pos as usize + self.length];
        buffer.set_position(pos + self.length as u64);
        Ok(())
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

        let mut buf = BufferMut::with_capacity(2u16);
        buf.deserialize_from(&mut c).unwrap();
        assert_eq!(buf.data, &[0x12, 0x34]);

        let mut buf = BufferMut::with_capacity(2u16);
        buf.deserialize_from(&mut c).unwrap();
        assert_eq!(buf.data, &[0x56, 0x78]);

        let mut buf = BufferMut::with_capacity(2u16);
        buf.deserialize_from(&mut c).unwrap();
        assert_eq!(buf.data, &[0x9A, 0xBC]);
    }
}
