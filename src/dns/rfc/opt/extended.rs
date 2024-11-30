use std::fmt;

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use serde::Serialize;

use crate::dns::buffer::Buffer;

// https://www.rfc-editor.org/rfc/rfc7871
#[derive(Debug, Default, ToNetwork, Serialize)]
pub struct Extended {
    pub(super) info_code: u16,
    pub(super) extra_text: Buffer,
}

impl From<(u16, Buffer)> for Extended {
    fn from(x: (u16, Buffer)) -> Self {
        Self {
            info_code: x.0,
            extra_text: x.1,
        }
    }
}

impl fmt::Display for Extended {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.info_code {
            1 => write!(f, "Other"),
            2 => write!(f, "Unsupported DNSKEY Algorithm"),
            3 => write!(f, "Unsupported DS Digest Type"),
            4 => write!(f, "Stale Answer"),
            5 => write!(f, "Forged Answer"),
            6 => write!(f, "DNSSEC Indeterminate"),
            7 => write!(f, "DNSSEC Bogus"),
            8 => write!(f, "Signature Expired"),
            9 => write!(f, "Signature Not Yet Valid"),
            10 => write!(f, "DNSKEY Missing"),
            11 => write!(f, "RRSIGs Missing"),
            12 => write!(f, "No Zone Key Bit Set"),
            13 => write!(f, "NSEC Missing"),
            14 => write!(f, "Cached Error"),
            15 => write!(f, "Not Ready"),
            16 => write!(f, "Blocked"),
            17 => write!(f, "Censored"),
            18 => write!(f, "Filtered"),
            19 => write!(f, "Prohibited"),
            20 => write!(f, "Stale NXDOMAIN Answer"),
            21 => write!(f, "Not Authoritative"),
            22 => write!(f, "Not Supported"),
            23 => write!(f, "No Reachable Authority"),
            24 => write!(f, "Network Error"),
            25 => write!(f, "Invalid Data"),
            _ => write!(f, "extended code {} not yet assigned", self.info_code),
        }
    }
}
