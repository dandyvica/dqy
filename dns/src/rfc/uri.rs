use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{buffer::Buffer, new_rd_length};

// https://datatracker.ietf.org/doc/html/rfc7553
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Priority             |          Weight               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                             Target                            /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, FromNetwork)]
pub(super) struct URI {
    #[deser(ignore)]
    rd_length: u16,

    priority: u16,
    weight: u16,

    #[deser(with_code( self.target = Buffer::new(self.rd_length - 4); ))]
    target: Buffer,
}

// auto-implement new
new_rd_length!(URI);

impl fmt::Display for URI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} \"{}\"",
            self.priority,
            self.weight,
            String::from_utf8_lossy(&self.target)
        )
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

    use super::URI;

    test_rdata!(
        "./tests/uri.pcap",
        RData::URI,
        (|x: &URI, _| {
            assert_eq!(
                &x.to_string(),
                "10 1 \"https://www.netmeister.org/blog/dns-rrs.html\""
            );
        })
    );
}
