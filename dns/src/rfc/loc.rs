use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

// LOC RR (https://datatracker.ietf.org/doc/html/rfc1876)
#[derive(Debug, Default, FromNetwork)]
pub struct LOC {
    pub(super) version: u8,
    pub(super) size: u8,
    pub(super) horiz_pre: u8,
    pub(super) vert_pre: u8,
    pub(super) latitude1: u16,
    pub(super) latitude2: u16,
    pub(super) longitude1: u16,
    pub(super) longitude2: u16,
    pub(super) altitude1: u16,
    pub(super) altitude2: u16,
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
