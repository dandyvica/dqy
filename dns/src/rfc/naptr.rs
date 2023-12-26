use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::{char_string::CharacterString, domain::DomainName};

// 1  1  1  1  1  1
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     ORDER                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   PREFERENCE                  |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                     FLAGS                     /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                   SERVICES                    /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                    REGEXP                     /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                  REPLACEMENT                  /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug, Default, FromNetwork)]
pub(super) struct NAPTR<'a> {
    order: u16,
    preference: u16,
    flags: CharacterString<'a>,
    services: CharacterString<'a>,
    regex: CharacterString<'a>,
    replacement: DomainName<'a>,
}

impl<'a> fmt::Display for NAPTR<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} ",
            self.order, self.preference, self.flags, self.services, self.regex, self.replacement
        )?;

        Ok(())
    }
}
