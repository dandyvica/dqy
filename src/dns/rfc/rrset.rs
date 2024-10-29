//! RRSet is a list of resource records for the same domain name.
//!
use std::{fmt, net::IpAddr, ops::Deref};

#[allow(unused_imports)]
use rand::seq::IteratorRandom;
use serde::Serialize;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::{domain::DomainName, qtype::QType, resource_record::ResourceRecord};
use crate::show::{Show, ShowOptions};

#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct RRSet(Vec<ResourceRecord>);

impl RRSet {
    // necessery for deserialization
    pub fn with_capacity(capa: usize) -> Self {
        Self(Vec::with_capacity(capa))
    }

    // in case a RR in the set is a A or AAAA type, return the corresponding ip address
    pub fn ip_address<T: TryInto<DomainName>>(&self, qt: &QType, name: T) -> Option<IpAddr> {
        let name = name.try_into().ok()?;

        let rr = self.0.iter().filter(|x| x.name == name && x.r#type == *qt).nth(0);

        if let Some(rr) = rr {
            rr.ip_address()
        } else {
            None
        }
    }

    // return a random RR corresponding to the QType
    pub fn random(&self, qt: &QType) -> Option<&ResourceRecord> {
        let mut rng = rand::thread_rng();

        self.0.iter().filter(|rr| rr.r#type == *qt).choose(&mut rng)
    }

    // return the maximum length of all domain names in all RRs in the RR set
    // used to align all domain names in output
    pub fn max_length(&self) -> Option<usize> {
        self.0.iter().map(|x| x.name.len()).max()
    }
}

impl Deref for RRSet {
    type Target = Vec<ResourceRecord>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for RRSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for rr in &self.0 {
            writeln!(f, "{}", rr)?;
        }

        Ok(())
    }
}

impl Show for RRSet {
    fn show(&self, display_options: &ShowOptions) {
        let max_length = if display_options.align_names {
            self.max_length()
        } else {
            None
        };

        for rr in &self.0 {
            // don't display OPT if not requested
            if rr.r#type == QType::OPT && !display_options.show_opt {
                continue;
            } else {
                rr.show(display_options, max_length);
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        dns::rfc::{domain::DomainName, qtype::QType, response::Response},
        dns::tests::get_packets,
    };
    use type2network::FromNetworkOrder;

    #[test]
    fn cap4() -> crate::error::Result<()> {
        let pcap = get_packets("./tests/pcap/cap4.pcap", 0, 1);
        let mut buffer = std::io::Cursor::new(&pcap.1[0x2A..]);

        let mut resp = Response::default();
        resp.deserialize_from(&mut buffer)?;

        // no anwser is response => this is a referral
        assert!(resp.is_referral());

        assert!(resp.authority.is_some());
        let auth = resp.authority.unwrap();
        assert_eq!(auth.len(), 13);

        assert!(resp.additional.is_some());
        let add = resp.additional.unwrap();
        assert_eq!(add.len(), 27);

        let ip = add.ip_address(&QType::A, "l.gtld-servers.net.").unwrap();
        assert_eq!(ip.to_string(), "192.41.162.30");
        let ip = add.ip_address(&QType::AAAA, "g.gtld-servers.net.").unwrap();
        assert_eq!(ip.to_string(), "2001:503:eea3::30");
        let ip = add.ip_address(&QType::AAAA, "foo.");
        assert!(ip.is_none());

        let d = DomainName::try_from("i.gtld-servers.net.").unwrap();
        let ip = add.ip_address(&QType::A, d).unwrap();
        assert_eq!(ip.to_string(), "192.43.172.30");

        // let answer = &answer[0];
        // assert_eq!(format!("{}", answer.name), "www.google.com.");
        // assert_eq!(answer.r#type, QType::A);
        // assert!(matches!(&answer.opt_or_else, OptOrElse::Regular(x) if x.class == QClass::IN));
        // assert!(matches!(&answer.opt_or_else, OptOrElse::Regular(x) if x.ttl == 119));
        // assert_eq!(answer.rd_length, 4);

        // assert!(
        //     matches!(answer.r_data, RData::A(A(addr)) if Ipv4Addr::from(addr) == Ipv4Addr::new(172,217,18,36))
        // );

        Ok(())
    }
}
