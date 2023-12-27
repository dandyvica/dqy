use std::{fmt, net::Ipv4Addr};

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

// A resource record
#[derive(Debug, Default, FromNetwork)]
pub struct A(pub(super) u32);

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Ipv4Addr::from(self.0))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::{
        error::DNSResult,
        rfc::{a::A, rdata::RData, response::Response},
        tests::{get_pcap_buffer, read_pcap_sample},
    };

    use type2network::FromNetworkOrder;

    #[test]
    fn rr_a() -> DNSResult<()> {
        let pcap = read_pcap_sample("./tests/a.pcap")?;
        let mut buffer = get_pcap_buffer(&pcap);

        let mut resp = Response::default();
        resp.deserialize_from(&mut buffer.buf_resp)?;

        let answer = resp.answer.unwrap();
        let answer = &answer[0];

        assert!(
            matches!(answer.r_data, RData::A(A(addr)) if Ipv4Addr::from(addr) == Ipv4Addr::new(166,84,7,99))
        );

        Ok(())
    }
}
