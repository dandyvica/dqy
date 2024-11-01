// EndPopint represents the resolver to be connected with.
// it can be:
// - a domain name, optionally starting with https
// - an ip address (v4 or v6)
// - a couple of ip:port
use std::{
    fmt,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
};

use resolver::ResolverList;

use super::network::IPVersion;
use super::root_servers::get_root_server;
use crate::error::{Error, Network};

#[derive(Debug, Clone)]
pub struct EndPoint {
    // value of the endpoint (e.g.: 1.1.1.1 or one.one.one.one)
    pub server: String,

    //value converted to a list of SocketAddr
    pub addrs: Vec<SocketAddr>,
}

impl EndPoint {
    // only keep IPV4 or IPV6 or both addresses
    pub fn retain(&mut self, ver: &IPVersion) {
        match ver {
            IPVersion::Any => (),
            IPVersion::V4 => self.addrs.retain(|ip| ip.is_ipv4()),
            IPVersion::V6 => self.addrs.retain(|ip| ip.is_ipv6()),
        }
    }
}

// Default endpoint will be a random root server
impl Default for EndPoint {
    fn default() -> Self {
        let rs = get_root_server(&IPVersion::V4, None);
        EndPoint::try_from((&rs, 53)).unwrap()
    }
}

impl fmt::Display for EndPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "server: {} addresses: {:?}", self.server, self.addrs)
    }
}

// build end point from the resolvers taken from a file
// e.g.: EndPoint::try_from(PathBuf::from("resolv.conf"), 53)
impl TryFrom<(&PathBuf, u16)> for EndPoint {
    type Error = crate::error::Error;

    fn try_from(value: (&PathBuf, u16)) -> Result<Self, Self::Error> {
        let resolvers = ResolverList::try_from(value.0.as_path()).map_err(|e| Error::Resolver(e))?;
        let ip_list = resolvers
            .to_ip_list()
            .iter()
            .map(|ip| SocketAddr::from((*ip, value.1)))
            .collect();

        Ok(Self {
            server: String::new(),
            addrs: ip_list,
        })
    }
}

// build endpoint when using a couple name:port
// e.g.: EndPoint::try_from("1.1.1.1:53") or https://2606:4700::6810:f9f9/dns-query
impl TryFrom<&str> for EndPoint {
    type Error = crate::error::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // e.g.: https://cloudflare-dns.com/dns-query
        if value.starts_with("https://") {
            Ok(Self {
                server: value.to_string(),
                ..Default::default()
            })
        }
        // e.g.: 1.1.1.1:53
        // or: [2606:4700:4700::1111]:53
        // or: one.one.one.one:53
        else {
            let addrs = value
                .to_socket_addrs()
                .map_err(|e| Error::Network(e, Network::SocketAddr))?;

            Ok(Self {
                server: value.to_string(),
                addrs: addrs.collect(),
            })
        }
    }
}

// build endpoint when using a couple (name, port)
// e.g.: EndPoint::try_from("1.1.1.1", 53) or EndPoint::try_from("one.one.one.one", 53)
impl TryFrom<(&str, u16)> for EndPoint {
    type Error = crate::error::Error;

    fn try_from(value: (&str, u16)) -> Result<Self, Self::Error> {
        EndPoint::try_from(format!("{}:{}", value.0, value.1).as_str())
    }
}

// build a endpoint when no server is provided. So we need to take
// the host resolver
// e.g.: EndPoint::try_from(53)
impl TryFrom<u16> for EndPoint {
    type Error = crate::error::Error;

    fn try_from(port: u16) -> Result<Self, Self::Error> {
        // if no server, use host resolvers
        let resolvers = ResolverList::new().map_err(|e| Error::Resolver(e))?;
        let ip_list = resolvers
            .to_ip_list()
            .iter()
            .map(|ip| SocketAddr::from((*ip, port)))
            .collect();

        Ok(Self {
            server: String::new(),
            addrs: ip_list,
        })
    }
}

impl TryFrom<(&IpAddr, u16)> for EndPoint {
    type Error = crate::error::Error;

    fn try_from(value: (&IpAddr, u16)) -> Result<Self, Self::Error> {
        let sockaddr = SocketAddr::from((*value.0, value.1));

        Ok(Self {
            server: String::new(),
            addrs: vec![sockaddr],
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, SocketAddr},
        path::PathBuf,
        str::FromStr,
    };

    use super::EndPoint;

    #[test]
    fn from_path() {
        let path = PathBuf::from("./tests/resolv.conf");
        let ep = EndPoint::try_from((&path, 53));
        assert!(ep.is_ok());

        let ep = ep.unwrap();
        assert_eq!(ep.addrs, vec![SocketAddr::from_str("1.1.1.1:53").unwrap()]);
    }

    #[test]
    fn from_string() {
        let ep = EndPoint::try_from("https://cloudflare-dns.com/dns-query");
        assert!(ep.is_ok());
        assert_eq!(&ep.unwrap().server, "https://cloudflare-dns.com/dns-query");

        let ep = EndPoint::try_from("https://104.16.249.249/dns-query");
        assert!(ep.is_ok());
        assert_eq!(&ep.unwrap().server, "https://104.16.249.249/dns-query");

        let ep = EndPoint::try_from("https://2606:4700::6810:f9f9/dns-query");
        assert!(ep.is_ok());
        assert_eq!(&ep.unwrap().server, "https://2606:4700::6810:f9f9/dns-query");

        let ep = EndPoint::try_from("1.1.1.1:53");
        assert!(ep.is_ok());
        assert_eq!(ep.unwrap().addrs, vec![SocketAddr::from_str("1.1.1.1:53").unwrap()]);

        // as Github runners don't support IPV6, use this trick.
        // if we want to run tests on runners locally, we have to define
        // a special env variable DQY_LOCAL_TEST, whatever the value
        if let Ok(_) = std::env::var("DQY_LOCAL_TEST") {
            let ep = EndPoint::try_from("[2606:4700:4700::1111]:53");
            assert!(ep.is_ok());
            assert_eq!(
                ep.unwrap().addrs,
                vec![SocketAddr::from_str("[2606:4700:4700::1111]:53").unwrap()]
            );

            let ep = EndPoint::try_from("one.one.one.one:53");
            assert!(ep.is_ok());
            let ep = ep.unwrap();
            assert!(ep.addrs.contains(&SocketAddr::from_str("1.1.1.1:53").unwrap()));
            assert!(ep.addrs.contains(&SocketAddr::from_str("1.0.0.1:53").unwrap()));
            assert!(ep
                .addrs
                .contains(&SocketAddr::from_str("[2606:4700:4700::1001]:53").unwrap()));
            assert!(ep
                .addrs
                .contains(&SocketAddr::from_str("[2606:4700:4700::1111]:53").unwrap()));
        }
    }

    #[test]
    fn from_name_port() {
        let ep = EndPoint::try_from(("1.1.1.1", 53));
        assert!(ep.is_ok());
        assert_eq!(ep.unwrap().addrs, vec![SocketAddr::from_str("1.1.1.1:53").unwrap()]);

        // as Github runners don't support IPV6, use this trick.
        // if we want to run tests on runners locally, we have to define
        // a special env variable DQY_LOCAL_TEST, whatever the value
        if let Ok(_) = std::env::var("DQY_LOCAL_TEST") {
            let ep = EndPoint::try_from(("one.one.one.one", 53));
            assert!(ep.is_ok());
            let ep = ep.unwrap();
            assert!(ep.addrs.contains(&SocketAddr::from_str("1.1.1.1:53").unwrap()));
            assert!(ep.addrs.contains(&SocketAddr::from_str("1.0.0.1:53").unwrap()));
            assert!(ep
                .addrs
                .contains(&SocketAddr::from_str("[2606:4700:4700::1001]:53").unwrap()));
            assert!(ep
                .addrs
                .contains(&SocketAddr::from_str("[2606:4700:4700::1111]:53").unwrap()));
        }
    }

    #[test]
    fn from_name_colon_port() {
        // as Github runners don't support IPV6, use this trick.
        // if we want to run tests on runners locally, we have to define
        // a special env variable DQY_LOCAL_TEST, whatever the value
        if let Ok(_) = std::env::var("DQY_LOCAL_TEST") {
            let ep = EndPoint::try_from("one.one.one.one:53");
            assert!(ep.is_ok());
            let ep = ep.unwrap();
            assert!(ep.addrs.contains(&SocketAddr::from_str("1.1.1.1:53").unwrap()));
            assert!(ep.addrs.contains(&SocketAddr::from_str("1.0.0.1:53").unwrap()));
            assert!(ep
                .addrs
                .contains(&SocketAddr::from_str("[2606:4700:4700::1001]:53").unwrap()));
            assert!(ep
                .addrs
                .contains(&SocketAddr::from_str("[2606:4700:4700::1111]:53").unwrap()));
        }
    }

    #[test]
    fn from_ip_only_port() {
        let ip = IpAddr::from_str("1.1.1.1").unwrap();
        let ep = EndPoint::try_from((&ip, 53));
        assert!(ep.is_ok());
        let ep = ep.unwrap();
        assert_eq!(ep.addrs, vec![SocketAddr::from_str("1.1.1.1:53").unwrap()]);
    }
}
