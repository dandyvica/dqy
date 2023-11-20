use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::char_string::CharacterString;

// MX RR
#[derive(Debug, Default, FromNetwork)]
pub struct TXT<'a>(pub CharacterString<'a>);

impl<'a> fmt::Display for TXT<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
