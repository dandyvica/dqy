use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::error;

#[derive(Debug, Default, Clone, PartialEq)]
pub enum IPVersion {
    #[default]
    Any,
    V4,
    V6,
}

// Bind to a socket either to IPV4, IPV6 or any of these 2
// the bind() method will chose the first one which succeeds if IPVersion::Any is passed
pub fn unspec(ver: &IPVersion) -> Vec<SocketAddr> {
    match ver {
        IPVersion::Any => vec![
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        ],
        IPVersion::V4 => vec![SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))],
        IPVersion::V6 => vec![SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))],
    }
}

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

#[allow(async_fn_in_trait)]
pub trait Messenger {
    // send query using the underlying transport
    fn send(&mut self, buffer: &[u8]) -> error::Result<usize>;

    // async version
    async fn asend(&mut self, buffer: &[u8]) -> error::Result<usize>;

    // receive response using the underlying transport
    fn recv(&mut self, buffer: &mut [u8]) -> error::Result<usize>;

    // async version
    async fn arecv(&mut self, buffer: &mut [u8]) -> error::Result<usize>;

    // true if transporter uses Tcp. This is required for TCP transport to have 2 bytes
    // for the message length prepended in the query
    fn uses_leading_length(&self) -> bool;

    // return the transport mode (udp, tcp, etc)
    fn mode(&self) -> Protocol;

    // return the local address used by the transport
    fn local(&self) -> std::io::Result<SocketAddr>;

    // return the remote address used by the transport
    fn peer(&self) -> std::io::Result<SocketAddr>;

    // return the network stats in the underlying structure
    fn netstat(&self) -> (usize, usize);
}

pub trait AsyncMessenger {
    // send query using the underlying transport
    async fn asend(&mut self, buffer: &[u8]) -> error::Result<usize>;

    // receive response using the underlying transport
    async fn arecv(&mut self, buffer: &mut [u8]) -> error::Result<usize>;

    // true if transporter uses Tcp. This is required for TCP transport to have 2 bytes
    // for the message length prepended in the query
    fn uses_leading_length(&self) -> bool;

    // return the transport mode (udp, tcp, etc)
    fn mode(&self) -> Protocol;
}

// utility functions
