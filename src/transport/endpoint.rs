// EndPopint represents the resolver to be connected with.
// it can be:
// - a domain name, optionally starting with https
// - an ip address (v4 or v6)
// - a couple of ip:port
use std::{
    fmt,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    str::FromStr,
};

use regex::Regex;
use resolving::ResolverList;

use super::network::IPVersion;
use crate::error::{Dns, Error, Result};

#[derive(Debug, Default, Clone)]
pub struct EndPoint {
    // value of the endpoint (e.g.: 1.1.1.1 or one.one.one.one)
    pub server_name: String,

    // port number
    pub port: u16,

    // value converted to a list of SocketAddr
    pub addrs: Vec<SocketAddr>,

    // possible SNI
    pub sni: Option<String>,
}

impl EndPoint {
    pub fn new(server: &str, port: u16) -> Result<Self> {
        // captures cases of having port number attached
        let re = Regex::new(r"\[?([\w\.:]+)\]?:(\d+)$").unwrap();

        let mut t = Self {
            server_name: server.to_string(),
            port: port,
            ..Default::default()
        };

        // 1st case: https://2606:4700::6810:f9f9/dns-query or @https://cloudflare-dns.com/dns-query
        if server.starts_with("https://") {
            t.server_name = server.to_string();

            // we don't calculate addresses in that case: reqwest doesn't need it
            return Ok(t);
        }
        // 2nd case: @quic://dns.adguard.com or @quic://94.140.15.15
        else if server.starts_with("quic://") {
            let index = server.find("//").unwrap();
            t.server_name = server[index + 2..].to_string();
        }
        // case of a true IPV6 address
        else if Self::is_ipv6(server) {
        }
        // 3rd case: @1.1.1.1:53 or @[2606:4700:4700::1111]:53 or @one.one.one.one:53
        else if let Some(cap) = re.captures(server) {
            t.server_name = cap[1].to_string();
            t.port = cap[2]
                .parse::<u16>()
                .map_err(|e| Error::Conversion(e, cap[2].to_string()))?;
        }
        // // other cases
        // else {
        //     t.server_name = server.to_string();
        // }

        // now we've set the server name, need to calculate its addresses
        t.addrs = (t.server_name.as_str(), t.port)
            .to_socket_addrs()
            .map_err(|e| Error::ToSocketAddrs(e, t.server_name.clone()))?
            .collect();

        // // if no ip address is resolved, the host name is probably bogus
        // if t.addrs.is_empty() {
        //     return Err(Error::Dns(Dns::DomainNameNotFound(t.server_name)));
        // }

        Ok(t)
    }

    // only keep IPV4 or IPV6 or both addresses' version
    pub fn retain(&mut self, ver: &IPVersion) {
        match ver {
            IPVersion::Any => (),
            IPVersion::V4 => self.addrs.retain(|ip| ip.is_ipv4()),
            IPVersion::V6 => self.addrs.retain(|ip| ip.is_ipv6()),
        }
    }

    // test if a string ip is IPV6. Used to disambiguate from cases where port is added
    fn is_ipv6(ip_str: &str) -> bool {
        matches!(IpAddr::from_str(ip_str), Ok(IpAddr::V6(_)))
    }

    // gives on random address of addr field
    pub fn random(&self, ip_version: &IPVersion) -> Option<SocketAddr> {
        match ip_version {
            IPVersion::Any | IPVersion::V4 => self.addrs.iter().find(|sa| sa.is_ipv4()).copied(),
            IPVersion::V6 => self.addrs.iter().find(|sa| sa.is_ipv6()).copied(),
        }
    }
}

// Default endpoint will be a random root server
// impl Default for EndPoint {
//     fn default() -> Self {
//         let rs = get_root_server(&IPVersion::V4, None);
//         EndPoint::try_from((&rs, 53)).unwrap()
//     }
// }

impl fmt::Display for EndPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "server: <{}> addresses: <{:?}>", self.server_name, self.addrs)
    }
}

// build end point from the resolvers taken from a file
// e.g.: EndPoint::try_from(PathBuf::from("resolv.conf"), 53)
impl TryFrom<(&PathBuf, u16)> for EndPoint {
    type Error = crate::error::Error;

    fn try_from(value: (&PathBuf, u16)) -> std::result::Result<Self, Self::Error> {
        let resolvers = ResolverList::try_from(value.0.as_path()).map_err(Error::Resolver)?;
        let ip_list = resolvers
            .to_ip_vec()
            .iter()
            .map(|ip| SocketAddr::from((*ip, value.1)))
            .collect();

        Ok(Self {
            server_name: String::new(),
            port: value.1,
            addrs: ip_list,
            sni: None,
        })
    }
}

// build a endpoint when no server is provided. So we need to take
// the host resolver
// e.g.: EndPoint::try_from(53)
impl TryFrom<u16> for EndPoint {
    type Error = crate::error::Error;

    fn try_from(port: u16) -> std::result::Result<Self, Self::Error> {
        // if no server, use host resolvers
        let resolvers = ResolverList::new().map_err(Error::Resolver)?;
        let ip_list = resolvers
            .to_ip_vec()
            .iter()
            .map(|ip| SocketAddr::from((*ip, port)))
            .collect();

        Ok(Self {
            server_name: String::new(),
            port: port,
            addrs: ip_list,
            sni: None,
        })
    }
}

impl TryFrom<(&IpAddr, u16)> for EndPoint {
    type Error = crate::error::Error;

    fn try_from(value: (&IpAddr, u16)) -> std::result::Result<Self, Self::Error> {
        let sockaddr = SocketAddr::from((*value.0, value.1));

        Ok(Self {
            server_name: value.0.to_string(),
            port: value.1,
            addrs: vec![sockaddr],
            sni: None,
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
    fn new() {
        // test with IPV6 on GitHub actions is not possible yet
        if std::env::var("GITHUB_REPOSITORY").is_err() {
            let ep = EndPoint::new("8.8.8.8", 53).unwrap();
            assert_eq!(&ep.server_name, "8.8.8.8");
            assert_eq!(ep.port, 53);
            assert!(ep.addrs.contains(&SocketAddr::from_str("8.8.8.8:53").unwrap()));

            let ep = EndPoint::new("2606:4700:4700::1111", 53).unwrap();
            assert_eq!(&ep.server_name, "2606:4700:4700::1111");
            assert_eq!(ep.port, 53);
            assert!(ep
                .addrs
                .contains(&SocketAddr::from_str("[2606:4700:4700::1111]:53").unwrap()));

            let ep = EndPoint::new("a.root-servers.net", 53).unwrap();
            assert_eq!(&ep.server_name, "a.root-servers.net");
            assert_eq!(ep.port, 53);
            assert!(ep.addrs.contains(&SocketAddr::from_str("198.41.0.4:53").unwrap()));

            let ep = EndPoint::new("https://cloudflare-dns.com/dns-query", 443).unwrap();
            assert_eq!(&ep.server_name, "https://cloudflare-dns.com/dns-query");
            assert_eq!(ep.port, 443);
            assert!(ep.addrs.is_empty());

            let ep = EndPoint::new("https://2606:4700::6810:f9f9/dns-query", 443).unwrap();
            assert_eq!(&ep.server_name, "https://2606:4700::6810:f9f9/dns-query");
            assert_eq!(ep.port, 443);
            assert!(ep.addrs.is_empty());

            let ep = EndPoint::new("quic://dns.adguard.com", 53).unwrap();
            assert_eq!(&ep.server_name, "dns.adguard.com");
            assert_eq!(ep.port, 53);
            assert!(ep.addrs.contains(&SocketAddr::from_str("94.140.15.15:53").unwrap()));
            assert!(ep.addrs.contains(&SocketAddr::from_str("94.140.14.14:53").unwrap()));

            let ep = EndPoint::new("quic://94.140.15.15", 53).unwrap();
            assert_eq!(&ep.server_name, "94.140.15.15");
            assert_eq!(ep.port, 53);
            assert!(ep.addrs.contains(&SocketAddr::from_str("94.140.15.15:53").unwrap()));

            let ep = EndPoint::new("quic://2a10:50c0::ad2:ff", 853).unwrap();
            assert_eq!(&ep.server_name, "2a10:50c0::ad2:ff");
            assert_eq!(ep.port, 853);
            assert!(ep
                .addrs
                .contains(&SocketAddr::from_str("[2a10:50c0::ad2:ff]:853").unwrap()));

            let ep = EndPoint::new("1.1.1.1:853", 53).unwrap();
            assert_eq!(&ep.server_name, "1.1.1.1");
            assert_eq!(ep.port, 853);
            assert!(ep.addrs.contains(&SocketAddr::from_str("1.1.1.1:853").unwrap()));

            let ep = EndPoint::new("[2606:4700:4700::1111]:853", 53).unwrap();
            assert_eq!(&ep.server_name, "2606:4700:4700::1111");
            assert_eq!(ep.port, 853);
            assert!(ep
                .addrs
                .contains(&SocketAddr::from_str("[2606:4700:4700::1111]:853").unwrap()));

            let ep = EndPoint::new("[2606:4700:4700::1111]:853", 53).unwrap();
            assert_eq!(&ep.server_name, "2606:4700:4700::1111");
            assert_eq!(ep.port, 853);
            assert!(ep
                .addrs
                .contains(&SocketAddr::from_str("[2606:4700:4700::1111]:853").unwrap()));

            let ep = EndPoint::new("one.one.one.one:853", 53).unwrap();
            assert_eq!(&ep.server_name, "one.one.one.one");
            assert_eq!(ep.port, 853);
            assert!(ep.addrs.contains(&SocketAddr::from_str("1.1.1.1:853").unwrap()));
            assert!(ep.addrs.contains(&SocketAddr::from_str("1.0.0.1:853").unwrap()));
            assert!(ep
                .addrs
                .contains(&SocketAddr::from_str("[2606:4700:4700::1001]:853").unwrap()));
            assert!(ep
                .addrs
                .contains(&SocketAddr::from_str("[2606:4700:4700::1111]:853").unwrap()));
        }
    }

    #[test]
    fn from_path() {
        let path = PathBuf::from("./tests/resolv.conf");
        let ep = EndPoint::try_from((&path, 53));
        assert!(ep.is_ok());

        let ep = ep.unwrap();
        assert_eq!(ep.addrs, vec![SocketAddr::from_str("1.1.1.1:53").unwrap()]);
    }

    // #[test]
    // fn from_string() {
    //     let ep = EndPoint::try_from("https://cloudflare-dns.com/dns-query");
    //     assert!(ep.is_ok());
    //     assert_eq!(&ep.unwrap().server_name, "https://cloudflare-dns.com/dns-query");

    //     let ep = EndPoint::try_from("https://104.16.249.249/dns-query");
    //     assert!(ep.is_ok());
    //     assert_eq!(&ep.unwrap().server_name, "https://104.16.249.249/dns-query");

    //     let ep = EndPoint::try_from("https://2606:4700::6810:f9f9/dns-query");
    //     assert!(ep.is_ok());
    //     assert_eq!(&ep.unwrap().server_name, "https://2606:4700::6810:f9f9/dns-query");

    //     let ep = EndPoint::try_from("1.1.1.1:53");
    //     assert!(ep.is_ok());
    //     assert_eq!(ep.unwrap().addrs, vec![SocketAddr::from_str("1.1.1.1:53").unwrap()]);

    //     // as Github runners don't support IPV6, use this trick.
    //     // if we want to run tests on runners locally, we have to define
    //     // a special env variable DQY_LOCAL_TEST, whatever the value
    //     if let Ok(_) = std::env::var("DQY_LOCAL_TEST") {
    //         let ep = EndPoint::try_from("[2606:4700:4700::1111]:53");
    //         assert!(ep.is_ok());
    //         assert_eq!(
    //             ep.unwrap().addrs,
    //             vec![SocketAddr::from_str("[2606:4700:4700::1111]:53").unwrap()]
    //         );

    //         let ep = EndPoint::try_from("one.one.one.one:53");
    //         assert!(ep.is_ok());
    //         let ep = ep.unwrap();
    //         assert!(ep.addrs.contains(&SocketAddr::from_str("1.1.1.1:53").unwrap()));
    //         assert!(ep.addrs.contains(&SocketAddr::from_str("1.0.0.1:53").unwrap()));
    //         assert!(ep
    //             .addrs
    //             .contains(&SocketAddr::from_str("[2606:4700:4700::1001]:53").unwrap()));
    //         assert!(ep
    //             .addrs
    //             .contains(&SocketAddr::from_str("[2606:4700:4700::1111]:53").unwrap()));
    //     }
    // }

    #[test]
    fn from_ip_only_port() {
        let ip = IpAddr::from_str("1.1.1.1").unwrap();
        let ep = EndPoint::try_from((&ip, 53));
        assert!(ep.is_ok());
        let ep = ep.unwrap();
        assert_eq!(ep.addrs, vec![SocketAddr::from_str("1.1.1.1:53").unwrap()]);
    }
}
