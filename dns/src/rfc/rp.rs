use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::domain::DomainName;

#[derive(Debug, Default, FromNetwork)]
pub(super) struct RP<'a> {
    mbox: DomainName<'a>,
    hostname: DomainName<'a>,
}

impl<'a> fmt::Display for RP<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ", self.mbox, self.hostname)
    }
}
