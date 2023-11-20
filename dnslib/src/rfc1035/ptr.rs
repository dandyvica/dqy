use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::domain::DomainName;

// CNAME resource record
#[derive(Debug, Default, FromNetwork)]
pub struct PTR<'a>(pub DomainName<'a>);

impl<'a> fmt::Display for PTR<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}