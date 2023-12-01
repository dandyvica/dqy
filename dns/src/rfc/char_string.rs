use std::fmt;
use std::io::{Cursor, Seek, SeekFrom};

use type2network::FromNetworkOrder;

// Character string as described in: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
#[derive(Debug, Default, PartialEq)]
pub struct CharacterString<'a> {
    pub length: u8,
    pub data: &'a [u8],
}

/// ```
/// use std::io::Cursor;
/// use dns::rfc::char_string::CharacterString;
///
/// let cs = CharacterString::from("www");
/// assert_eq!(cs.length, 3u8);
/// assert_eq!(cs.data, &[119, 119, 119]);
/// ```  
impl<'a> From<&'a str> for CharacterString<'a> {
    fn from(s: &'a str) -> Self {
        CharacterString {
            length: s.len() as u8,
            data: s.as_bytes(),
        }
    }
}

/// ```
/// use std::io::Cursor;
/// use dns::rfc::char_string::CharacterString;
///
/// let cs = CharacterString::from("www");
/// //assert_eq!(cs.to_string(), "www");
/// ```
impl<'a> fmt::Display for CharacterString<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", String::from_utf8_lossy(self.data))
    }
}

impl<'a> FromNetworkOrder<'a> for CharacterString<'a> {
    /// ```
    /// use std::io::Cursor;
    /// use type2network::FromNetworkOrder;
    /// use dns::rfc::char_string::CharacterString;
    ///
    /// let mut buffer = Cursor::new([0x06_u8, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65].as_slice());
    /// let mut cs = CharacterString::default();
    /// assert!(cs.deserialize_from(&mut buffer).is_ok());
    /// assert_eq!(cs.length, 6u8);
    /// assert_eq!(std::str::from_utf8(cs.data).unwrap(), "google");
    /// ```    
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        // copy text length
        self.length.deserialize_from(buffer)?;
        let current_position = buffer.position() as usize;

        // slice to data
        self.data = &buffer.get_ref()[current_position..current_position + self.length as usize];

        // don't forget to move the position
        buffer.seek(SeekFrom::Current(self.length as i64))?;

        Ok(())
    }
}
