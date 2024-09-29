use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{buffer::Buffer, new_rd_length};

// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Cert. Usage  |   Selector    | Matching Type |               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               /
// /                                                               /
// /                 Certificate Association Data                  /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, FromNetwork)]
pub(super) struct TLSA {
    #[from_network(ignore)]
    rd_length: u16,

    cert_usage: u8,
    selector: u8,
    matching_type: u8,

    #[from_network(with_code( self.data = Buffer::with_capacity(self.rd_length - 3); ))]
    data: Buffer,
}

// auto-implement new
new_rd_length!(TLSA);

impl fmt::Display for TLSA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {:?}",
            self.cert_usage, self.selector, self.matching_type, self.data
        )
    }
}

// Custom serialization
use serde::{ser::SerializeMap, Serialize, Serializer};
impl Serialize for TLSA {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(4))?;
        seq.serialize_entry("cert_usage", &self.cert_usage)?;
        seq.serialize_entry("selector", &self.selector)?;
        seq.serialize_entry("matching_type", &self.matching_type)?;
        seq.serialize_entry("data", &self.data.to_string())?;
        seq.end()
    }
}

// https://datatracker.ietf.org/doc/html/rfc8162
#[allow(clippy::upper_case_acronyms)]
pub(super) type SMIMEA = TLSA;

#[cfg(test)]
mod tests {
    use crate::{
        rfc::{rdata::RData, response::Response},
        test_rdata,
        tests::get_packets,
    };

    use type2network::FromNetworkOrder;

    use super::{SMIMEA, TLSA};

    test_rdata!(
        rdata_tlsa,
        "./tests/tlsa.pcap",
        false,
        1,
        RData::TLSA,
        (|x: &TLSA, _| {
            assert_eq!(
                &x.to_string(),
                "3 1 1 8CE14CBE1FAFAE9FB25845D335E0E416BC2FAE02E8746689C06DA59C1F9382"
            );
        })
    );

    test_rdata!(
        rdata_smimea,
        "./tests/smimea.pcap",
        false,
        1,
        RData::SMIMEA,
        (|x: &SMIMEA, _| {
            assert_eq!(
                &x.to_string(),
                "3 1 1 8CE14CBE1FAFAE9FB25845D335E0E416BC2FAE02E8746689C06DA59C1F9382"
            );
        })
    );
}
