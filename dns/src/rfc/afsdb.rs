use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::domain::DomainName;

#[derive(Debug, Default, FromNetwork)]
pub(super) struct AFSDB<'a> {
    subtype: u16,
    hostname: DomainName<'a>,
}

impl<'a> fmt::Display for AFSDB<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ", self.subtype, self.hostname)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use crate::{
        error::DNSResult,
        rfc::{afsdb::AFSDB, rdata::RData, response::Response},
        tests::{get_pcap_buffer, read_pcap_sample},
    };

    use type2network::FromNetworkOrder;

    #[test]
    fn rr_aaaa() -> DNSResult<()> {
        let pcap = read_pcap_sample("./tests/afsdb.pcap")?;
        let mut buffer = get_pcap_buffer(&pcap);

        let mut resp = Response::default();
        resp.deserialize_from(&mut buffer.buf_resp)?;

        let answer = resp.answer.unwrap();
        let answer = &answer[0];

        assert!(
            matches!(&answer.r_data, RData::AFSDB(AFSDB { subtype: x, hostname }) if x == &1u16 && &hostname.to_string() == "panix.netmeister.org.")
        );

        Ok(())
    }
}
