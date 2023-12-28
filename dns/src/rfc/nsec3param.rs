use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;
//use type2network_derive::FromNetwork;

use crate::buffer::Buffer;

// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Hash Alg.   |     Flags     |          Iterations           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Salt Length  |                     Salt                      /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, FromNetwork)]
pub struct NSEC3PARAM {
    algorithm: u8,
    flags: u8,
    iterations: u16,
    salt_length: u8,

    #[deser(with_code( self.salt = Buffer::new(self.salt_length); ))]
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
            "{} {} {} {}",
            self.algorithm, self.flags, self.iterations, self.salt
        )?;
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

    use super::NSEC3PARAM;

    test_rdata!(
        "./tests/nsec3param.pcap",
        RData::NSEC3PARAM,
        (|x: &NSEC3PARAM, _| {
            assert_eq!(&x.to_string(), "1 0 15 CB49105466D36AD");
        })
    );
}
