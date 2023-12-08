use byteorder::ReadBytesExt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use enum_from::{EnumDisplay, EnumTryFrom};

/// op codes: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
#[derive(Debug, Default, Clone, Copy, PartialEq, FromNetwork, EnumTryFrom, EnumDisplay)]
#[repr(u8)]
pub enum OpCode {
    #[default]
    Query = 0, //[RFC1035]
    IQuery = 1, // (Inverse Query, OBSOLETE)	[RFC3425]
    Status = 2, // [RFC1035]
    Unassigned = 3,
    Notify = 4, // [RFC1996]
    Update = 5, // [RFC2136]
    DOS = 6,    // DNS Stateful Operations (DSO)	[RFC8490]
                // 7-15 Unassigned
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::from_network_test;

    #[test]
    fn network() {
        let q = OpCode::DOS;
        from_network_test(None, &q, &vec![0x06]);
    }
}
