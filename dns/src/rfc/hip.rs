use std::fmt;

// use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use base16::encode_upper;
use base64::{engine::general_purpose, Engine as _};

use crate::{buffer::Buffer, new_rd_length};

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
    #[deser(ignore)]
    pub(super) rd_length: u16,

    hit_length: u8,
    pk_algorithm: u8,
    pk_length: u16,

    #[deser(with_code( self.hit = Buffer::new(self.hit_length); ))]
    hit: Buffer,

    #[deser(with_code( self.public_key = Buffer::new(self.pk_length); ))]
    public_key: Buffer,

    #[deser(with_code( self.rendezvous_servers = Buffer::new(self.rd_length - 4 - self.hit_length as u16 - self.pk_length); ))]
    rendezvous_servers: Buffer,
}

// auto-implement new
new_rd_length!(HIP);

impl fmt::Display for HIP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hit_b64 = base16::encode_upper(&self.hit);
        let pk_b64 = general_purpose::STANDARD.encode(&self.public_key);
        write!(f, "{} {} {}", self.pk_algorithm, hit_b64, pk_b64)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::DNSResult,
        rfc::{rdata::RData, response::Response},
        test_rdata,
        tests::{get_pcap_buffer, read_pcap_sample},
    };

    use type2network::FromNetworkOrder;

    use super::HIP;

    test_rdata!(
        rdata,
        "./tests/hip.pcap",
        RData::HIP,
        (|x: &HIP, _| {
            assert_eq!(&x.to_string(), "2 200100107B1A74DF365639CC39F1D578 AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D");
        })
    );
}
