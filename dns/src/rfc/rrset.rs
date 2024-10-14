//! RRSet is a list of resource records for the same domain name.
//!

use std::{net::IpAddr, ops::Deref};

use show::Show;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

#[allow(unused_imports)]
use rand::seq::IteratorRandom;
use serde::Serialize;

use super::{
    domain::DomainName,
    qtype::{self, QType},
    resource_record::ResourceRecord,
};

#[derive(Debug, Default, FromNetwork, Serialize)]
pub(super) struct RRSet(Vec<ResourceRecord>);

impl RRSet {
    // necessery for deserialization
    pub fn with_capacity(capa: usize) -> Self {
        Self(Vec::with_capacity(capa))
    }

    // return a list of RRs having the same QType
    // pub fn filter(&self, qt: &QType) -> Vec<&RR> {
    //     self.0.iter().filter(|x| x.r#type == *qt).collect()
    // }

    // in case a RR in the set is a A or AAAA type, return the corresponding ip address
    pub fn ip_address<'a, T: TryInto<DomainName>>(&self, qt: &QType, name: T) -> Option<IpAddr>
    where
        <T as TryInto<DomainName>>::Error: std::fmt::Debug,
    {
        let name = name.try_into().unwrap();

        let rr = self
            .0
            .iter()
            .filter(|x| x.name == name && x.r#type == *qt)
            .nth(0);
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
}

impl Deref for RRSet {
    type Target = Vec<ResourceRecord>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Show for RRSet {
    fn show(&self, display_options: &show::DisplayOptions) {
        for rr in &self.0 {
            rr.show(display_options);
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        rfc::{qtype::QType, response::Response},
        tests::get_packets,
    };
    use type2network::FromNetworkOrder;

    #[test]
    fn cap4() -> error::Result<()> {
        let pcap = get_packets("./tests/cap4.pcap", 0, 1);
        let mut buffer = std::io::Cursor::new(&pcap.1[0x2A..]);

        let mut resp = Response::default();
        resp.deserialize_from(&mut buffer)?;

        assert!(resp.answer.is_none());

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
