use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use super::domain::DomainName;

// LOC RR (https://datatracker.ietf.org/doc/html/rfc1876)
#[derive(Debug, Default, FromNetwork)]
pub struct LOC {
    pub version: u8,
    pub size: u8,
    pub horiz_pre: u8,
    pub vert_pre: u8,
    pub latitude1: u16,
    pub latitude2: u16,
    pub longitude1: u16,
    pub longitude2: u16,
    pub altitude1: u16,
    pub altitude2: u16,
}

impl fmt::Display for LOC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "version:{} size:{} horiz_pre:{} vert_pre:{} latitude1:{} latitude2:{} longitude1:{} longitude2:{} altitude1:{} altitude2:{}",
            self.version,
            self.size,
            self.horiz_pre,
            self.vert_pre,
            self.latitude1,
            self.latitude2,
            self.longitude1,
            self.longitude2,
            self.altitude1,
            self.altitude2,
        )
    }
}
