use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

use super::domain::DomainName;

// SOA RR
#[derive(Debug, Default, PartialEq, FromNetwork, Serialize)]
pub struct SOA {
    pub mname: DomainName, // The <domain-name> of the name server that was the
    // original or primary source of data for this zone.
    pub rname: DomainName, // A <domain-name> which specifies the mailbox of the
    // person responsible for this zone.
    pub serial: u32, // The unsigned 32 bit version number of the original copy
    // of the zone.  Zone transfers preserve this value.  This
    // value wraps and should be compared using sequence space
    // arithmetic.
    pub refresh: u32, // A 32 bit time interval before the zone should be
    // refreshed.
    pub retry: u32, // A 32 bit time interval that should elapse before a
    // failed refresh should be retried.
    pub expire: u32, // A 32 bit time value that specifies the upper limit on
    // the time interval that can elapse before the zone is no
    // longer authoritative.
    pub minimum: u32, //The unsigned 32 bit minimum TTL field that should be
                      //exported with any RR from this zone.
}

impl fmt::Display for SOA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {}",
            self.mname, self.rname, self.serial, self.refresh, self.retry, self.expire, self.minimum
        )
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

    use super::SOA;

    test_rdata!(
        rdata,
        "./tests/pcap/soa.pcap",
        false,
        1,
        RData::SOA,
        (|x: &SOA, _| {
            assert_eq!(
                &x.to_string(),
                "panix.netmeister.org. jschauma.netmeister.org. 2021072599 3600 300 3600000 3600"
            );
        })
    );
}
