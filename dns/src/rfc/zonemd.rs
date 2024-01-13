use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{databuf::BufferMut, new_rd_length};

// https://www.rfc-editor.org/rfc/rfc8976
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             Serial                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    Scheme     |Hash Algorithm |                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
// |                             Digest                            |
// /                                                               /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, FromNetwork)]
pub(super) struct ZONEMD<'a> {
    #[deser(ignore)]
    rd_length: u16,

    serial: u32,
    scheme: u8,
    hash_algorithm: u8,

    #[deser(with_code( self.digest = BufferMut::with_capacity(self.rd_length - 6); ))]
    digest: BufferMut<'a>,
}

// auto-implement new
new_rd_length!(ZONEMD<'a>);

impl<'a> fmt::Display for ZONEMD<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {:?}",
            self.serial, self.scheme, self.hash_algorithm, self.digest
        )
    }
}

// Custom serialization
use serde::{ser::SerializeMap, Serialize, Serializer};
impl<'a> Serialize for ZONEMD<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(4))?;
        seq.serialize_entry("serial", &self.serial)?;
        seq.serialize_entry("scheme", &self.scheme)?;
        seq.serialize_entry("hash_algorithm", &self.hash_algorithm)?;
        seq.serialize_entry("digest", &self.digest.to_string())?;
        seq.end()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        rfc::{rdata::RData, response::Response},
        test_rdata,
        tests::get_packets,
    };

    use type2network::FromNetworkOrder;

    use super::ZONEMD;

    test_rdata!(
        rdata,
        "./tests/zonemd.pcap",
        false,
        1,
        RData::ZONEMD,
        (|x: &ZONEMD, _| {
            assert_eq!(&x.to_string(), "2021071219 1 1 4274F6BC562CF8CE512B21AAA4CCC1EB9F4FAAAECD01642D0A07BDEA890C8845849D615CC590F54BAC7E87B9E41ED");
        })
    );
}
