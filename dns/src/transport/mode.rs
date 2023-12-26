#[derive(Debug, Default, PartialEq)]
pub enum IPVersion {
    #[default]
    V4,
    V6,
}

#[derive(Debug, Default, PartialEq)]
pub enum TransportMode {
    #[default]
    Udp,
    Tcp,
    DoH,
    DoT,
}

impl TransportMode {
    // default port number for transport or port
    pub fn default_port(&self) -> u16 {
        match self {
            TransportMode::Udp => 53,
            TransportMode::Tcp => 53,
            TransportMode::DoT => 853,
            TransportMode::DoH => 443,
        }
    }
}
