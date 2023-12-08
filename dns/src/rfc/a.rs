use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

// A resource record
#[derive(Debug, Default, FromNetwork)]
pub struct A(pub(super) u32);

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", std::net::Ipv4Addr::from(self.0))
    }
}
