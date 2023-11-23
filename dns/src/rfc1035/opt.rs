use std::fmt;
use std::io::Cursor;

use byteorder::{BigEndian, ReadBytesExt};

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

#[derive(Debug, Default, FromNetwork)]
pub struct ExtendedRcode {
    pub extented_rcode: u8,
    pub version: u8,
    pub doz: u16,
}

#[derive(Debug, Default)]
pub struct OPT {
    pub code: u16,
    pub length: u16,
    pub data: Vec<u8>,
}

impl<'a> FromNetworkOrder<'a> for OPT {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        self.code.deserialize_from(buffer)?;
        self.length.deserialize_from(buffer)?;

        self.data = Vec::with_capacity(self.length as usize);
        self.data.deserialize_from(buffer)?;

        Ok(())
    }
}

impl fmt::Display for OPT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "code={}, length={}", self.code, self.length)
    }
}
