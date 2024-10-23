use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde::Serialize;

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
    Serialize,
)]
#[repr(u16)]
#[from_network(TryFrom)]
pub enum QClass {
    #[default]
    IN = 1, // the Internet
    CS = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // the CHAOS class
    HS = 4, // Hesiod [Dyer 87]
    ANY = 255,

    #[fallback]
    CLASS(u16),
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::dns::tests::{from_network_test, to_network_test};

    #[test]
    fn conversion() {
        use std::str::FromStr;

        // from_str
        let qc = QClass::from_str("IN").unwrap();
        assert_eq!(qc, QClass::IN);
        let qc = QClass::from_str("foo").unwrap_err();
        assert_eq!(qc, format!("no variant corresponding to value 'foo'"));
        let qc = QClass::from_str("CLASS1234").unwrap();
        assert_eq!(qc, QClass::CLASS(1234));
        let qc = QClass::from_str("CLASSA234").unwrap_err();
        assert_eq!(qc, format!("no variant corresponding to value 'CLASSA234'"));

        // try_from
        let qc = QClass::try_from(4u16).unwrap();
        assert_eq!(qc, QClass::HS);
        let qc = QClass::try_from(1000u16).unwrap();
        assert_eq!(qc, QClass::CLASS(1000));

        // display
        let qc = QClass::from_str("IN").unwrap();
        assert_eq!(&qc.to_string(), "IN");
        let qc = QClass::try_from(2u16).unwrap();
        assert_eq!(&qc.to_string(), "CS");
        let qc = QClass::try_from(1000u16).unwrap();
        assert_eq!(&qc.to_string(), "CLASS1000");
        let qc = QClass::from_str("CLASS1234").unwrap();
        assert_eq!(&qc.to_string(), "CLASS1234");
    }

    #[test]
    fn network() {
        let q = QClass::ANY;
        to_network_test(&q, 2, &[0x00, 0xFF]);
        from_network_test(None, &q, &vec![0x00, 0xFF]);
    }
}
