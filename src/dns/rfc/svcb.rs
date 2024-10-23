use std::{fmt, io::Cursor};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use enum_from::{EnumDisplay, EnumFromStr, EnumTryFrom};
use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use super::domain::DomainName;

use crate::{dns::buffer::Buffer, new_rd_length};

// https://datatracker.ietf.org/doc/html/rfc9460#section-14.3.2
// +===========+=================+================+=========+==========+
// |   Number  | Name            | Meaning        |Reference|Change    |
// |           |                 |                |         |Controller|
// +===========+=================+================+=========+==========+
// |     0     | mandatory       | Mandatory      |RFC 9460,|IETF      |
// |           |                 | keys in this   |Section 8|          |
// |           |                 | RR             |         |          |
// +-----------+-----------------+----------------+---------+----------+
// |     1     | alpn            | Additional     |RFC 9460,|IETF      |
// |           |                 | supported      |Section  |          |
// |           |                 | protocols      |7.1      |          |
// +-----------+-----------------+----------------+---------+----------+
// |     2     | no-default-alpn | No support     |RFC 9460,|IETF      |
// |           |                 | for default    |Section  |          |
// |           |                 | protocol       |7.1      |          |
// +-----------+-----------------+----------------+---------+----------+
// |     3     | port            | Port for       |RFC 9460,|IETF      |
// |           |                 | alternative    |Section  |          |
// |           |                 | endpoint       |7.2      |          |
// +-----------+-----------------+----------------+---------+----------+
// |     4     | ipv4hint        | IPv4 address   |RFC 9460,|IETF      |
// |           |                 | hints          |Section  |          |
// |           |                 |                |7.3      |          |
// +-----------+-----------------+----------------+---------+----------+
// |     5     | ech             | RESERVED       |N/A      |IETF      |
// |           |                 | (held for      |         |          |
// |           |                 | Encrypted      |         |          |
// |           |                 | ClientHello)   |         |          |
// +-----------+-----------------+----------------+---------+----------+
// |     6     | ipv6hint        | IPv6 address   |RFC 9460,|IETF      |
// |           |                 | hints          |Section  |          |
// |           |                 |                |7.3      |          |
// +-----------+-----------------+----------------+---------+----------+
// |65280-65534| N/A             | Reserved for   |RFC 9460 |IETF      |
// |           |                 | Private Use    |         |          |
// +-----------+-----------------+----------------+---------+----------+
// |   65535   | N/A             | Reserved       |RFC 9460 |IETF      |
// |           |                 | ("Invalid      |         |          |
// |           |                 | key")          |         |          |
// +-----------+-----------------+----------------+---------+----------+
#[allow(clippy::upper_case_acronyms)]
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    PartialEq,
    EnumFromStr,
    EnumTryFrom,
    EnumDisplay,
    ToNetwork,
    FromNetwork,
)]
#[repr(u16)]
#[allow(non_camel_case_types)]
#[allow(clippy::unnecessary_cast)]
#[from_network(TryFrom)]
pub(super) enum SvcParamKeys {
    #[default]
    mandatory = 0_u16,
    alpn = 1,
    no_default_alpn = 2,
    port = 3,
    ipv4hint = 4,
    ech = 5,
    ipv6hint = 6,

    #[fallback]
    RESERVED(u16),
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default)]
#[allow(non_camel_case_types)]
#[allow(clippy::unnecessary_cast)]
pub(super) struct SvcParam {
    // param key:  2-octet field containing the SvcParamKey as an integer in network byte order
    key: u16,
    length: u16,
    value: Buffer,
}

impl SvcParam {
    pub fn len(&self) -> usize {
        4 + self.value.len()
    }
}

impl fmt::Display for SvcParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.key {
            1 => write!(f, "alpn=\"{}\"", self.value)?,
            4 => {
                if self.length % 4 == 0 {
                    let ip_array: [u8; 4] = self.value[0..4].try_into().unwrap();
                    write!(f, "ipv4hint={}", std::net::Ipv4Addr::from(ip_array))?;
                }
            }
            6 => {
                if self.length == 16 {
                    let ip_array: [u8; 16] = self.value[0..16].try_into().unwrap();
                    write!(f, "ipv6hint={}", std::net::Ipv6Addr::from(ip_array))?;
                }
            }
            _ => unimplemented!("SvcParamKeys {} is not yet implemented", self.key),
        }

        Ok(())
    }
}

// https://www.rfc-editor.org/rfc/rfc9460.txt
#[derive(Debug, Default)]
pub struct SVCB {
    // transmistted through RR deserialization
    //#[from_network(ignore)]
    pub(super) rd_length: u16,

    svc_priority: u16,
    target_name: DomainName,

    //#[from_network(with_code( self.svc_params = BufferMut::with_capacity(self.rd_length - 2 - self.target_name.len() as u16); ))]
    svc_params: Vec<SvcParam>,
}

// auto-implement new
new_rd_length!(SVCB);

// implement FromNetwork because of the special SVCB format
impl<'a> FromNetworkOrder<'a> for SVCB {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        self.svc_priority.deserialize_from(buffer)?;
        self.target_name.deserialize_from(buffer)?;

        // remaining length for Vec<SvcParam>
        let data_length = self.rd_length - 2u16 - self.target_name.len() as u16;
        let mut current_length = 0u16;

        // now deserialize each SvcParam
        while current_length < data_length {
            let mut param = SvcParam::default();
            param.key.deserialize_from(buffer)?;
            param.length.deserialize_from(buffer)?;

            param.value = Buffer::with_capacity(param.length);
            param.value.deserialize_from(buffer)?;

            current_length += param.len() as u16;

            self.svc_params.push(param);
        }

        Ok(())
    }
}

impl fmt::Display for SVCB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ", self.svc_priority, self.target_name)?;
        for param in &self.svc_params {
            write!(f, "{} ", param)?;
        }

        Ok(())
    }
}

// Custom serialization
use serde::{ser::SerializeMap, Serialize, Serializer};
impl Serialize for SVCB {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(2))?;
        seq.serialize_entry("svc_priority", &self.svc_priority)?;
        seq.serialize_entry("target_name", &self.target_name)?;
        seq.end()
    }
}

// HTTPS is like SVCB
#[allow(clippy::upper_case_acronyms)]
pub(super) type HTTPS = SVCB;

// #[cfg(test)]
// mod tests {
//     use crate::{
//         error::DNSResult,
//         dns::rfc::{rdata::RData, response::Response},
//         test_rdata,
//         dns::tests::get_packets,
//     };

//     use type2network::FromNetworkOrder;

//     use super::SVCB;

//     test_rdata!(
//         rdata,
//         "./tests/pcap/svcb.pcap",
//         RData::SVCB,
//         (|x: &SVCB, _| {
//             assert_eq!(&x.to_string(), "");
//         })
//     );
// }
