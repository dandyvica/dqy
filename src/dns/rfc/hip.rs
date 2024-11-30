use std::fmt;

// use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{dns::buffer::Buffer, new_rd_length};

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
pub struct HIP {
    // transmistted through RR deserialization
    #[from_network(ignore)]
    pub(super) rd_length: u16,

    hit_length: u8,
    pk_algorithm: u8,
    pk_length: u16,

    #[from_network(with_code( self.hit = Buffer::with_capacity(self.hit_length); ))]
    hit: Buffer,

    #[from_network(with_code( self.public_key = Buffer::with_capacity(self.pk_length); ))]
    public_key: Buffer,

    #[from_network(with_code( self.rendezvous_servers = Buffer::with_capacity(self.rd_length - 4 - self.hit_length as u16 - self.pk_length); ))]
    rendezvous_servers: Buffer,
}

// auto-implement new
new_rd_length!(HIP);

impl fmt::Display for HIP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.pk_algorithm,
            self.hit.to_base16(),
            self.public_key.to_base64()
        )
    }
}

// Custom serialization
use serde::{ser::SerializeMap, Serialize, Serializer};
impl Serialize for HIP {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(3))?;
        seq.serialize_entry("pk_algorithm", &self.pk_algorithm)?;
        seq.serialize_entry("hit", &self.hit.to_base16())?;
        seq.serialize_entry("public_key", &self.public_key.to_base64())?;
        seq.end()
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

    use super::HIP;

    test_rdata!(
        rdata,
        "./tests/pcap/hip.pcap",
        false,
        1,
        RData::HIP,
        (|x: &HIP, _| {
            assert_eq!(&x.to_string(), "2 200100107B1A74DF365639CC39F1D578 AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D");
        })
    );
}
