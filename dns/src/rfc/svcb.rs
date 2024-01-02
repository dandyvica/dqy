use std::fmt;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use enum_from::{EnumDisplay, EnumFromStr, EnumTryFrom};
use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use super::domain::DomainName;

use crate::{buffer::Buffer, new_rd_length};

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

// https://www.rfc-editor.org/rfc/rfc9460.txt
#[derive(Debug, Default, FromNetwork)]
pub struct SVCB<'a> {
    // transmistted through RR deserialization
    #[deser(ignore)]
    pub(super) rd_length: u16,

    svc_priority: u16,
    target_name: DomainName<'a>,

    #[deser(with_code( self.svc_params = Buffer::new(self.rd_length - 2 - self.target_name.len() as u16); ))]
    svc_params: Buffer,
}

// auto-implement new
new_rd_length!(SVCB<'a>);

impl<'a> fmt::Display for SVCB<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.svc_priority, self.target_name, self.svc_params
        )?;

        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::{
//         error::DNSResult,
//         rfc::{rdata::RData, response::Response},
//         test_rdata,
//         tests::get_packets,
//     };

//     use type2network::FromNetworkOrder;

//     use super::SVCB;

//     test_rdata!(
//         rdata,
//         "./tests/svcb.pcap",
//         RData::SVCB,
//         (|x: &SVCB, _| {
//             assert_eq!(&x.to_string(), "");
//         })
//     );
// }
