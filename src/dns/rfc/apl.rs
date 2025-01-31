use std::{
    fmt,
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr},
};

use log::trace;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{dns::buffer::Buffer, new_rd_length};

//───────────────────────────────────────────────────────────────────────────────────
// InnerAPL
//───────────────────────────────────────────────────────────────────────────────────
// https://www.rfc-editor.org/rfc/rfc3123.html
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// |                          ADDRESSFAMILY                        |
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// |             PREFIX            | N |         AFDLENGTH         |
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// /                            AFDPART                            /
// |                                                               |
// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, FromNetwork)]
pub(super) struct InnerAPL {
    address_family: u16,
    prefix: u8,
    afdlength: u8,

    #[from_network(with_code( let length = (self.afdlength << 1) >> 1; trace!("afdlength={}", length); self.afdpart = Buffer::with_capacity(length); ))]
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
                write!(f, "{}{}:{}/{}", n, self.address_family, ip, self.prefix)?;
            }
            2 => {
                let mut ip = [0u8; 16];
                (0..length).for_each(|i| ip[i as usize] = self.afdpart[i as usize]);
                let ip = Ipv6Addr::from(ip);
                write!(f, "{}{}:{}/{}", n, self.address_family, ip, self.prefix)?;
            }
            _ => unimplemented!("only IPV4 or V6 for APL"),
        }

        Ok(())
    }
}

// Custom serialization
use serde::{Serialize, Serializer};
impl Serialize for InnerAPL {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

//───────────────────────────────────────────────────────────────────────────────────
// APL
//───────────────────────────────────────────────────────────────────────────────────
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, Serialize)]
pub struct APL {
    #[serde(skip_serializing)]
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

#[cfg(test)]
mod tests {
    use crate::{
        dns::rfc::{rdata::RData, response::Response},
        dns::tests::get_packets,
        test_rdata,
    };

    use type2network::FromNetworkOrder;

    use super::APL;

    test_rdata!(
        rdata,
        "./tests/pcap/apl.pcap",
        false,
        1,
        RData::APL,
        (|x: &APL, _| {
            assert_eq!(x.apl.len(), 4);
            assert_eq!(&x.apl[0].to_string(), "1:192.168.32.0/21");
            assert_eq!(&x.apl[1].to_string(), "!1:192.168.38.0/28");
            assert_eq!(&x.apl[2].to_string(), "2:2001:db8::/32");
            assert_eq!(&x.apl[3].to_string(), "!2:2001:470:30:84::/64");
        })
    );
}
