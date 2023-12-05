use std::{default, fmt, io::Cursor};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use enum_from::{EnumDisplay, EnumTryFrom};
use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use crate::buffer::Buffer;

// NSID: https://www.rfc-editor.org/rfc/rfc5001.html
#[derive(Debug, Default, ToNetwork)]
pub(super) struct NSID(Option<Buffer>);

impl From<Buffer> for NSID {
    fn from(buf: Buffer) -> Self {
        Self(Some(buf))
    }
}

impl<'a> fmt::Display for NSID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_some() {
            let buf = self.0.as_ref().unwrap();
            for c in buf.into_iter() {
                write!(f, "{:0X?} ", c)?;
            }
            for c in buf.into_iter() {
                write!(f, "{}", *c as char)?;
            }
        }

        Ok(())
    }
}
