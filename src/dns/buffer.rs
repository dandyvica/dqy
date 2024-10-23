// A specific management for the Vec<u8> type for the FromNetworkOrder trait
use std::convert::AsRef;
use std::fmt;
use std::io::{Cursor, Read};
use std::ops::Deref;

use base64::{engine::general_purpose, Engine as _};

use type2network::{FromNetworkOrder, ToNetworkOrder};

#[derive(Default)]
pub struct Buffer(Vec<u8>);

impl Buffer {
    pub fn with_capacity<T: Into<usize>>(len: T) -> Self {
        Self(vec![0; len.into()])
    }

    // when printing out some RRs, it's easier to use this
    // pub fn to_string(&self) -> String {
    //     String::from_utf8_lossy(&self.0).to_string()
    // }

    // some RRs need to convert the raw data into b16 or b64 hexa strings
    pub fn to_b64(&self) -> String {
        general_purpose::STANDARD.encode(self.as_ref())
    }

    // some RRs need to convert the raw data into b16 or b64 hexa strings
    pub fn to_b16(&self) -> String {
        base16::encode_upper(&self.as_ref())
    }

    // useful for JSON output
    pub fn to_hex(&self) -> String {
        format!("{:?}", self)
    }
}

impl Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.iter() {
            write!(f, "{:X?}", c)?;
        }
        Ok(())
    }
}

impl fmt::Display for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = String::from_utf8_lossy(self.0.as_ref()).to_string();
        write!(f, "{}", s)
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

// Custom serialization
use serde::{Serialize, Serializer};
impl Serialize for Buffer {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub(crate) fn serialize_buffer<S>(owner: &Buffer, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&owner.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::tests::to_network_test;
    use std::io::Cursor;
    use type2network::FromNetworkOrder;

    #[test]
    fn network() {
        // to
        let mut buf = Buffer::with_capacity(3u16);
        buf.0 = vec![0, 1, 2];
        to_network_test(&buf, 3, &[0, 1, 2]);

        // from
        let b = vec![0x12, 0x34, 0x56, 0x78];
        let mut buffer = Cursor::new(b.as_slice());
        let mut buf = Buffer::with_capacity(2u16);
        assert!(buf.deserialize_from(&mut buffer).is_ok());
        assert_eq!(buf.as_ref(), &[0x12, 0x34]);
        assert!(buf.deserialize_from(&mut buffer).is_ok());
        assert_eq!(buf.as_ref(), &[0x56, 0x78]);
    }
}
