// A specific management for the Vec<u8> type for the FromNetworkOrder trait
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
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        buffer.read_exact(self.0.as_mut_slice())?;
        Ok(())
    }
}

use std::convert::AsRef;

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
