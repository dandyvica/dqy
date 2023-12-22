use std::io::Result;
use std::net::{IpAddr, TcpStream, UdpSocket};
use std::net::{SocketAddr, ToSocketAddrs};
use std::vec::IntoIter;

pub enum Endpoint {
    // the resolver is given in the command line as an argument
    Manual(String),

    // the resolvers are taken from quering the OS configuration
    OS(Vec<IpAddr>),
}

pub struct EndpointAddrs {
    pub port: u16,
    pub endpoint: Endpoint,
}

impl From<&str> for Endpoint {
    fn from(s: &str) -> Self {
        Endpoint::Manual(s.to_string())
    }
}

impl From<&[IpAddr]> for Endpoint {
    fn from(s: &[IpAddr]) -> Self {
        Endpoint::OS(s.to_vec())
    }
}

impl ToSocketAddrs for EndpointAddrs {
    type Iter = IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> Result<Self::Iter> {
        match &self.endpoint {
            // ip addresses or host names are coming the command line
            Endpoint::Manual(addr) => {
                let addr = format!("{addr}:{}", self.port);
                addr.to_socket_addrs()
            }
            // ip addresses are coming from the machine resolver list
            Endpoint::OS(v) => {
                let addrs: Vec<SocketAddr> = v
                    .into_iter()
                    .map(|x| SocketAddr::from((*x, self.port)))
                    .collect();
                Ok(addrs.into_iter())
            }
        }
    }
}
