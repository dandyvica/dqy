use std::fmt;
use std::io::{Cursor, Seek, SeekFrom};
use std::ops::Deref;

use type2network::FromNetworkOrder;

use serde::{Serialize, Serializer};

use super::DataLength;

// Character string as described in: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
#[derive(Debug, Default, PartialEq)]
pub struct CharacterString {
    length: u8,
    data: Vec<u8>,
}

impl CharacterString {
    #[inline]
    pub fn len(&self) -> u8 {
        self.length
    }
}

impl DataLength for CharacterString {
    fn size(&self) -> u16 {
        self.length as u16 + 1
    }
}

impl From<&str> for CharacterString {
    fn from(s: &str) -> Self {
        CharacterString {
            length: s.len() as u8,
            data: s.as_bytes().to_vec(),
        }
    }
}

impl fmt::Display for CharacterString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.data))
    }
}

impl Serialize for CharacterString {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'a> FromNetworkOrder<'a> for CharacterString {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        // copy text length
        self.length.deserialize_from(buffer)?;
        let current_position = buffer.position() as usize;

        // slice to data
        let s = &buffer.get_ref()[current_position..current_position + self.length as usize];
        self.data = s.to_vec();

        // don't forget to move the position
        buffer.seek(SeekFrom::Current(self.length as i64))?;

        Ok(())
    }
}

// in some contexts, we need to deal with a buffer containing continuous CharacterString
// like TXT RR or SVCB alpn param
#[derive(Debug, Default)]
pub struct CSList(Vec<CharacterString>);

// IntoIterator to benefit from already defined iterator on Vec
impl<'a> IntoIterator for &'a CSList {
    type Item = &'a CharacterString;
    type IntoIter = std::slice::Iter<'a, CharacterString>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl Deref for CSList {
    type Target = Vec<CharacterString>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&[u8]> for CSList {
    fn from(s: &[u8]) -> Self {
        let mut v = Vec::new();
        let mut index = 0;

        while index < s.len() {
            let length = s[index] as usize;
            let cs = CharacterString {
                length: length as u8,
                data: s[index + 1..index + length + 1].to_vec(),
            };
            v.push(cs);

            index += length + 1;
        }
        CSList(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn from() {
        let cs = CharacterString::from("www");
        assert_eq!(cs.length, 3u8);
        assert_eq!(cs.data, &[119, 119, 119]);
    }

    #[test]
    fn display() {
        let cs = CharacterString::from("www");
        assert_eq!(cs.to_string(), "www");
    }

    #[test]
    fn deserialize_from() {
        use type2network::FromNetworkOrder;
        let mut buffer = Cursor::new([0x06_u8, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65].as_slice());
        let mut cs = CharacterString::default();
        assert!(cs.deserialize_from(&mut buffer).is_ok());
        assert_eq!(cs.length, 6u8);
        assert_eq!(std::str::from_utf8(&cs.data).unwrap(), "google");
    }
}
