// On the cli, we can provide a string to match an ip (1.1.1.1) or a server name (one.one.one.one)
// or a DoH https address. If nothing is provided, a list of resolvers on the machine is fetched & queried.

use std::{
    net::SocketAddr,
    net::{IpAddr, ToSocketAddrs},
    vec::IntoIter,
};

#[derive(Debug)]
pub enum EndPoint {
    // either an ip address like 1.1.1.1, or a SNI name like one.one.one.one
    // or an https address like https://dns.google/dns-query
    Server(String, u16),

    // the list of ip addresses taken from the OS' resolvers
    IpList(Vec<IpAddr>, u16),
}

impl EndPoint {
    pub fn server(&self) -> Option<&str> {
        match self {
            Self::Server(d, _) => Some(d),
            _ => None,
        }
    }

    pub fn ip_list(&self) -> Option<&[IpAddr]> {
        match self {
            Self::IpList(d, _) => Some(d),
            _ => None,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Server(_, p) => *p,
            Self::IpList(_, p) => *p,
        }
    }
}

impl From<(&str, u16)> for EndPoint {
    fn from(value: (&str, u16)) -> Self {
        EndPoint::Server(value.0.to_string(), value.1)
    }
}

impl<'a> From<(&'a [IpAddr], u16)> for EndPoint {
    fn from(value: (&'a [IpAddr], u16)) -> Self {
        EndPoint::IpList(value.0.to_vec(), value.1)
    }
}

impl Default for EndPoint {
    fn default() -> Self {
        Self::Server("127.0.0.1".to_string(), 53)
    }
}

impl ToSocketAddrs for EndPoint {
    type Iter = IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<IntoIter<SocketAddr>> {
        match &self {
            EndPoint::Server(domain, port) => (domain.to_string(), *port).to_socket_addrs(),
            EndPoint::IpList(addrs, port) => {
                let socket_addresses: Vec<SocketAddr> = addrs
                    .iter()
                    .map(|ip| SocketAddr::from((*ip, *port)))
                    .collect();

                Ok(socket_addresses.into_iter())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn endpoint_ip() {
        let ep = EndPoint::from(("1.1.1.1", 53));
        let sa = ep.to_socket_addrs().unwrap();
        let v: Vec<_> = sa.into_iter().collect();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].to_string(), "1.1.1.1:53");
    }

    #[test]
    fn endpoint_name() {
        let ep = EndPoint::from(("one.one.one.one", 53));
        let sa = ep.to_socket_addrs().unwrap();
        let v: Vec<_> = sa.into_iter().map(|a| a.to_string()).collect();
        assert_eq!(v.len(), 4);
        assert!(v.contains(&"1.1.1.1:53".to_string()));
        assert!(v.contains(&"1.0.0.1:53".to_string()));
    }

    #[test]
    fn endpoint_iplist() {
        let ips = vec![
            IpAddr::from_str("2.2.2.2").unwrap(),
            IpAddr::from_str("3.3.3.3").unwrap(),
        ];

        let ep = EndPoint::from((&ips[..], 53));
        let sa = ep.to_socket_addrs().unwrap();
        let v: Vec<_> = sa.into_iter().map(|a| a.to_string()).collect();
        assert_eq!(v.len(), 2);
        assert!(v.contains(&"2.2.2.2:53".to_string()));
        assert!(v.contains(&"3.3.3.3:53".to_string()));
    }
}
