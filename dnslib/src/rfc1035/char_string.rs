use std::fmt;
use std::io::{Cursor, Seek, SeekFrom};

use type2network::FromNetworkOrder;

// Character string as described in: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
#[derive(Debug, Default, PartialEq)]
pub struct CharacterString<'a> {
    pub length: u8,
    pub data: &'a str,
}

/// ```
/// use std::io::Cursor;
/// use dnslib::rfc1035::char_string::CharacterString;
///
/// let cs = CharacterString::from("www");
/// assert_eq!(cs.length, 3u8);
/// assert_eq!(cs.data, "www");
/// ```  
impl<'a> From<&'a str> for CharacterString<'a> {
    fn from(s: &'a str) -> Self {
        CharacterString {
            length: s.len() as u8,
            data: s,
        }
    }
}

/// ```
/// use std::io::Cursor;
/// use dnslib::rfc1035::char_string::CharacterString;
///
/// let cs = CharacterString::from("www");
/// assert_eq!(cs.to_string(), "www");
/// ```
impl<'a> fmt::Display for CharacterString<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.data)
    }
}

impl<'a> FromNetworkOrder<'a> for CharacterString<'a> {
    /// ```
    /// use std::io::Cursor;
    /// use type2network::FromNetworkOrder;
    /// use dnslib::rfc1035::char_string::CharacterString;
    ///
    /// let mut buffer = Cursor::new([0x06_u8, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65].as_slice());
    /// let mut cs = CharacterString::default();
    /// assert!(cs.deserialize_from(&mut buffer).is_ok());
    /// assert_eq!(cs.length, 6u8);
    /// assert_eq!(cs.data, "google");
    /// ```    
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        // get a reference on [u8]
        let position = buffer.position() as usize;
        let inner_data = buffer.get_ref();

        // first char is the string length
        self.length = inner_data[position] as u8;

        // move the cursor forward
        buffer.seek(SeekFrom::Current(self.length as i64))?;

        // save data
        self.data = std::str::from_utf8(
            &buffer.get_ref()[position + 1..position + self.length as usize + 1],
        )
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to deserialize CharacterString",
            )
        })?;
        Ok(())
    }
}
