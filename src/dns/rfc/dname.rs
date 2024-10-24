//! Definition of the DNAME record (https://datatracker.ietf.org/doc/html/rfc6672#section-2.1)
use std::fmt;

// use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

use super::domain::DomainName;

// https://www.rfc-editor.org/rfc/rfc7477.html#section-2.1
// <owner> <ttl> <class> DNAME <target>
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct DNAME<'a>(DomainName<'a>);

impl<'a> fmt::Display for DNAME<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        dns::rfc::{rdata::RData, response::Response},
        test_rdata,
        dns::tests::get_packets,
    };

    use type2network::FromNetworkOrder;

    use super::DNAME;

    test_rdata!(
        rdata,
        "./tests/pcap/dname.pcap",
        false,
        1,
        RData::DNAME,
        (|x: &DNAME, _| {
            assert_eq!(&x.to_string(), "dns.netmeister.org.");
        })
    );
}
