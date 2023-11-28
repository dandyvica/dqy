// Resolver can be a dotted address and a domain name for DoT/DoH
pub enum Resolver {
    // For UDP it's a regular ip address list
    Udp(Vec<IpAddr>),

    // so is for TCP
    Tcp(Vec<IpAddr>),

    // but for DoT it's a domain name
    DoT(String)

    // for DoH
}

impl Resolver {
    pub fn new(s: &str, mode: TransportMode) -> Self {
        match mode {
            
        }
    }
}

