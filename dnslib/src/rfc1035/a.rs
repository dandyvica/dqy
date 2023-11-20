use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

// A resource record
#[derive(Debug, Default, FromNetwork)]
pub struct A(pub u32);

impl<'a> fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", std::net::Ipv4Addr::from(self.0))
    }
}
