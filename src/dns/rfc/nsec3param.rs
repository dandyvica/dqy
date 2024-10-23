use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;
//use type2network_derive::FromNetwork;

use crate::dns::buffer::Buffer;

// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Hash Alg.   |     Flags     |          Iterations           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Salt Length  |                     Salt                      /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[allow(clippy::len_without_is_empty)]
#[derive(Debug, Default, FromNetwork)]
pub struct NSEC3PARAM {
    algorithm: u8,
    flags: u8,
    iterations: u16,
    salt_length: u8,

    #[from_network(with_code( self.salt = Buffer::with_capacity(self.salt_length); ))]
    salt: Buffer,
}

impl NSEC3PARAM {
    pub fn len(&self) -> usize {
        5usize + self.salt_length as usize
    }
}

impl fmt::Display for NSEC3PARAM {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {:?}",
            self.algorithm, self.flags, self.iterations, self.salt
        )?;
        Ok(())
    }
}

// Custom serialization
use serde::{ser::SerializeMap, Serialize, Serializer};
impl Serialize for NSEC3PARAM {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(4))?;
        seq.serialize_entry("algorithm", &self.algorithm)?;
        seq.serialize_entry("flags", &self.flags)?;
        seq.serialize_entry("iterations", &self.iterations)?;
        seq.serialize_entry("salt", &self.salt.to_hex())?;
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

    use super::NSEC3PARAM;

    test_rdata!(
        rdata,
        "./tests/pcap/nsec3param.pcap",
        false,
        1,
        RData::NSEC3PARAM,
        (|x: &NSEC3PARAM, _| {
            assert_eq!(&x.to_string(), "1 0 15 CB49105466D36AD");
        })
    );
}
