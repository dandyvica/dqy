use std::fmt;

// use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{databuf::BufferMut, new_rd_length};

// https://datatracker.ietf.org/doc/html/rfc5205.html#section-5
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  HIP length   | PK algorithm  |          PK length            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// ~                           HIP                                 ~
// |                                                               |
// +                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     |                                         |
// +-+-+-+-+-+-+-+-+-+-+-+                                         +
// |                           Public Key                          |
// ~                                                               ~
// |                                                               |
// +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                               |                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
// |                                                               |
// ~                       Rendezvous Servers                      ~
// |                                                               |
// +             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             |
// +-+-+-+-+-+-+-+
#[derive(Debug, Default, FromNetwork)]
pub struct HIP<'a> {
    // transmistted through RR deserialization
    #[deser(ignore)]
    pub(super) rd_length: u16,

    hit_length: u8,
    pk_algorithm: u8,
    pk_length: u16,

    #[deser(with_code( self.hit = BufferMut::with_capacity(self.hit_length); ))]
    hit: BufferMut<'a>,

    #[deser(with_code( self.public_key = BufferMut::with_capacity(self.pk_length); ))]
    public_key: BufferMut<'a>,

    #[deser(with_code( self.rendezvous_servers = BufferMut::with_capacity(self.rd_length - 4 - self.hit_length as u16 - self.pk_length); ))]
    rendezvous_servers: BufferMut<'a>,
}

// auto-implement new
new_rd_length!(HIP<'a>);

impl<'a> fmt::Display for HIP<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.pk_algorithm,
            self.hit.as_b16(),
            self.public_key.as_b64()
        )
    }
}

// Custom serialization
use serde::{ser::SerializeMap, Serialize, Serializer};
impl<'a> Serialize for HIP<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(3))?;
        seq.serialize_entry("pk_algorithm", &self.pk_algorithm)?;
        seq.serialize_entry("hit", &self.hit.as_b16())?;
        seq.serialize_entry("public_key", &self.public_key.as_b64())?;
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

    use super::HIP;

    test_rdata!(
        rdata,
        "./tests/hip.pcap",
        false,
        1,
        RData::HIP,
        (|x: &HIP, _| {
            assert_eq!(&x.to_string(), "2 200100107B1A74DF365639CC39F1D578 AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D");
        })
    );
}
