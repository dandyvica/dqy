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
