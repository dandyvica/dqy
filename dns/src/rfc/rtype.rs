use std::fmt;
use std::io::Cursor;

// this is the response type which is sometimes different from the query type (QType)

use byteorder::{BigEndian, ReadBytesExt};
use type2network::FromNetworkOrder;

use super::qtype::QType;

#[derive(Debug, Copy, Clone)]
pub enum RType {
    QType(QType),

    // sometimes, the RType is not recognized in the list of QTypes
    Unknown(u16),
}

impl Default for RType {
    fn default() -> Self {
        RType::QType(QType::default())
    }
}

/// ```
/// use std::io::Cursor;
/// use dns::rfc::rtype::RType;
/// use dns::rfc::qtype::QType;
/// use type2network::FromNetworkOrder;
///
/// let mut buffer = Cursor::new([0xFE, 0xFF].as_slice());
/// let mut rt = RType::default();
/// assert!(rt.deserialize_from(&mut buffer).is_ok());
/// assert!(matches!(rt, RType::Unknown(x) if x == 0xFEFF));
///
/// let mut buffer = Cursor::new([0x00, 0x01].as_slice());
/// let mut rt = RType::default();
/// assert!(rt.deserialize_from(&mut buffer).is_ok());
/// assert!(matches!(rt, RType::QType(q) if q == QType::A));
/// ```
impl<'a> FromNetworkOrder<'a> for RType {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        let value = buffer.read_u16::<BigEndian>()?;

        match QType::try_from(value as u64) {
            Ok(q) => *self = RType::QType(q),
            Err(_) => *self = RType::Unknown(value),
        }

        Ok(())
    }
}

impl fmt::Display for RType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RType::QType(a) => write!(f, "{}", a),
            RType::Unknown(x) => write!(f, "{}", format!("TYPE{}", x)),
        }
    }
}
