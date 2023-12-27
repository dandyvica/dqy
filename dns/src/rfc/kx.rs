use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use base64::{engine::general_purpose, Engine as _};

use crate::{buffer::Buffer, new_rd_length};

use super::{algorithm::Algorithm, domain::DomainName};

// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                  PREFERENCE                   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// /                   EXCHANGER                   /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug, Default, FromNetwork)]
pub(super) struct KX<'a> {
    preference: u16,
    exchanger: DomainName<'a>,
}

impl<'a> fmt::Display for KX<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ", self.preference, self.exchanger)
    }
}
