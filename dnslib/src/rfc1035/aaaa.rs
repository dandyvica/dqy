use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

// AAAA resource record
#[derive(Debug, Default, FromNetwork)]
pub struct AAAA(pub [u8; 16]);

impl<'a> fmt::Display for AAAA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", std::net::Ipv6Addr::from(self.0))
    }
}
