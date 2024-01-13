// On the cli, we can provide a string to match an ip (1.1.1.1) or a server name (one.one.one.one)
// or a DoH https address. If nothing is provided, a list of resolvers on the machine is fetched & queried.

use std::{
    net::SocketAddr,
    net::{IpAddr, ToSocketAddrs},
    vec::IntoIter,
};

pub enum EndPoint<'a> {
    // either an ip address like 1.1.1.1, or a SNI name like one.one.one.one
    // or an https address like https://dns.google/dns-query
    Domain(&'a str),

    // the list of ip addresses taken for the OS' resolvers
    List(Vec<IpAddr>),
}

impl<'a> EndPoint<'a> {
    pub fn domain(&self) -> Option<&str> {
        match self {
            Self::Domain(d) => Some(d),
            _ => None,
        }
    }
}

// newtype to allow implementing ToSocketAddrs
pub struct EndPointSocketAddrs<'a>(EndPoint<'a>, u16);

impl<'a> EndPointSocketAddrs<'a> {
    pub fn endpoint(&self) -> &EndPoint<'a> {
        &self.0
    }
}

impl<'a> From<(&'a str, u16)> for EndPointSocketAddrs<'a> {
    fn from(value: (&'a str, u16)) -> Self {
        Self(EndPoint::Domain(value.0), value.1)
    }
}

impl<'a> From<(&'a [IpAddr], u16)> for EndPointSocketAddrs<'a> {
    fn from(value: (&'a [IpAddr], u16)) -> Self {
        Self(EndPoint::List(value.0.to_vec()), value.1)
    }
}

impl<'a> ToSocketAddrs for EndPointSocketAddrs<'a> {
    type Iter = IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<IntoIter<SocketAddr>> {
        match &self.0 {
            EndPoint::Domain(domain) => (domain.to_string(), self.1).to_socket_addrs(),
            EndPoint::List(addrs) => {
                let socket_addresses: Vec<SocketAddr> = addrs
                    .iter()
                    .map(|ip| SocketAddr::from((*ip, self.1)))
                    .collect();

                Ok(socket_addresses.into_iter())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint() {
        let ep = EndPointSocketAddrs(EndPoint::Domain("1.1.1.1"), 53);
        // let f = ep.to_socket_addrs().unwrap();
        // println!("f=============> {:?}", f.into_iter().collect::<Vec<SocketAddr>>());
        // assert_eq!(ep.to_socket_addrs().iter().collect::Vec<_>(), [""]);
        assert_eq!(ep.endpoint().domain().unwrap(), "1.1.1.1");
    }
}
