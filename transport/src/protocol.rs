use std::fmt;

#[derive(Debug, Default, Clone, PartialEq)]
pub enum IPVersion {
    #[default]
    Any,
    V4,
    V6,
}

// impl IPVersion {
//     // return the QType corresponding to the ip version, to get an ip address
//     pub fn adress_qtype(&self) -> QType {
//         match self {
//             IPVersion::Any, IPVersion::V4 => QType::A,
//             IPVersion::V6 => QType::AAAA
//         }
//     }
// }

#[derive(Debug, Default, Clone, PartialEq)]
pub enum Protocol {
    #[default]
    Udp,
    Tcp,
    DoH,
    DoT,
    DoQ,
}

impl Protocol {
    // default port number for transport or port
    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::Udp => 53,
            Protocol::Tcp => 53,
            Protocol::DoT => 853,
            Protocol::DoH => 443,
            Protocol::DoQ => 853,
        }
    }

    // true if message needs to be sent with prepended length
    pub fn uses_leading_length(&self) -> bool {
        *self == Protocol::Tcp || *self == Protocol::DoT
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Udp => write!(f, "Udp"),
            Protocol::Tcp => write!(f, "Tcp"),
            Protocol::DoT => write!(f, "DoT"),
            Protocol::DoH => write!(f, "DoH"),
            Protocol::DoQ => write!(f, "DoQ"),
        }
    }
}
