use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::domain::DomainName;

// MX RR
#[derive(Debug, Default, FromNetwork)]
pub struct MX<'a> {
    pub preference: u16, // A 16 bit integer which specifies the preference given to
    // this RR among others at the same owner.  Lower values
    // are preferred.
    pub exchange: DomainName<'a>, // A <domain-name> which specifies a host willing to act as a mail exchange for the owner name.
}

impl<'a> fmt::Display for MX<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.exchange,)
    }
}
