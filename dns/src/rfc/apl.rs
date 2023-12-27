use std::{
    fmt,
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr},
    ops::Deref,
};

use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use base64::{engine::general_purpose, Engine as _};

use crate::{buffer::Buffer, new_rd_length};

use super::algorithm::Algorithm;

// https://www.rfc-editor.org/rfc/rfc3123.html
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// |                          ADDRESSFAMILY                        |
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// |             PREFIX            | N |         AFDLENGTH         |
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// /                            AFDPART                            /
// |                                                               |
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
#[derive(Debug, Default, FromNetwork)]
pub(super) struct InnerAPL {
    address_family: u16,
    prefix: u8,
    afdlength: u8,

    #[deser(with_code( let length = (self.afdlength << 1) >> 1; trace!("afdlength={}", length); self.afdpart = Buffer::new(length); ))]
    afdpart: Buffer,
}

impl fmt::Display for InnerAPL {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // get rid of 'N'
        let length = (self.afdlength << 1) >> 1;

        // prepend address with '!' if N == 1
        let n = if self.afdlength >> 7 == 1 {
            String::from('!')
        } else {
            String::new()
        };

        match self.address_family {
            1 => {
                let mut ip = [0u8; 4];
                (0..length).for_each(|i| ip[i as usize] = self.afdpart[i as usize]);
                let ip = Ipv4Addr::from(ip);
                write!(f, "{}{}:{}/{} ", n, self.address_family, ip, self.prefix)?;
            }
            2 => {
                let mut ip = [0u8; 16];
                (0..length).for_each(|i| ip[i as usize] = self.afdpart[i as usize]);
                let ip = Ipv6Addr::from(ip);
                write!(f, "{}{}:{}/{} ", n, self.address_family, ip, self.prefix)?;
            }
            _ => unimplemented!("only IPV4 or V6 for APL"),
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
pub(super) struct APL {
    rd_length: u16,
    apl: Vec<InnerAPL>,
}

// auto-implement new
new_rd_length!(APL);

impl<'a> FromNetworkOrder<'a> for APL {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        let mut inner_length = 0;

        while inner_length < self.rd_length {
            let mut inner = InnerAPL::default();
            inner.deserialize_from(buffer)?;

            // get rid of 'N'
            let afdlength = ((inner.afdlength << 1) >> 1) as u16;
            inner_length += 4 + afdlength;

            // save into vector
            self.apl.push(inner);
        }

        Ok(())
    }
}

impl fmt::Display for APL {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for a in &self.apl {
            write!(f, "{} ", a)?;
        }

        Ok(())
    }
}