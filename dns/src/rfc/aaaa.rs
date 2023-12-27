use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

// AAAA resource record
#[derive(Debug, Default, Clone, FromNetwork)]
pub struct AAAA([u8; 16]);

impl fmt::Display for AAAA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", std::net::Ipv6Addr::from(self.0))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use crate::{
        error::DNSResult,
        rfc::{aaaa::AAAA, rdata::RData, response::Response},
        tests::{get_pcap_buffer, read_pcap_sample},
    };

    use type2network::FromNetworkOrder;

    #[test]
    fn rr_aaaa() -> DNSResult<()> {
        let pcap = read_pcap_sample("./tests/aaaa.pcap")?;
        let mut buffer = get_pcap_buffer(&pcap);

        let mut resp = Response::default();
        resp.deserialize_from(&mut buffer.buf_resp)?;

        let answer = resp.answer.unwrap();
        let answer = &answer[0];

        assert!(
            matches!(answer.r_data, RData::AAAA(AAAA(x)) if Ipv6Addr::from(x).to_string() == "2001:470:30:84:e276:63ff:fe72:3900")
        );

        Ok(())
    }
}
