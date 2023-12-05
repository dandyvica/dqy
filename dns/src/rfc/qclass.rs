use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use enum_from::{EnumDisplay, EnumFromStr, EnumTryFrom};
use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    PartialEq,
    EnumFromStr,
    EnumTryFrom,
    EnumDisplay,
    ToNetwork,
    FromNetwork,
)]
#[repr(u16)]
pub enum QClass {
    #[default]
    IN = 1, // the Internet
    CS = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // the CHAOS class
    HS = 4, // Hesiod [Dyer 87]
    ANY = 255,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{from_network_test, to_network_test};

    #[test]
    fn network() {
        let q = QClass::ANY;
        to_network_test(&q, 2, &[0x00, 0xFF]);
        from_network_test(None, &q, &vec![0x00, 0xFF]);
    }
}
