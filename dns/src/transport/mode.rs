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
    pub fn is_dot(&self) -> bool {
        matches!(self, TransportMode::DoT)
    }

    pub fn uses_tcp(&self) -> bool {
        matches!(self, TransportMode::Tcp)
            || matches!(self, TransportMode::DoT)
            || matches!(self, TransportMode::DoH)
    }

    pub fn uses_tls(&self) -> bool {
        matches!(self, TransportMode::DoT) || matches!(self, TransportMode::DoH)
    }
}
