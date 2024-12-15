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

use regex::Regex;
use resolving::ResolverList;

use super::network::IPVersion;
use super::root_servers::get_root_server;
use crate::error::{Error, Network, Result};

#[derive(Debug, Default, Clone)]
pub struct Target {
    // value of the endpoint (e.g.: 1.1.1.1 or one.one.one.one)
    pub server_name: String,

    // value converted to a list of SocketAddr
    pub addrs: Vec<SocketAddr>,

    pub port: u16,

    // possible SNI
    pub sni: Option<String>,
}

impl Target {
    pub fn new(server: &str, port: u16) -> Result<Self> {
        // captures cases of having port number attached
        let re = Regex::new(r"\[?([\w\.:]+)\]?:(\d+)$").unwrap();

        let mut t = Target::default();
        t.port = port;

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
        // 3rd case: @1.1.1.1:53 or @[2606:4700:4700::1111]:53 or @one.one.one.one:53
        else if let Some(cap) = re.captures(server) {
            t.server_name = cap[1].to_string();
            t.port = cap[2]
                .parse::<u16>()
                .map_err(|e| Error::Conversion(e, cap[2].to_string()))?;
        }
        // other cases
        else {
            t.server_name = server.to_string();
        }

        println!("================> {}", t.server_name);
        println!("================> {}", t.port);

        // now we've set the server name, need to calculate its addresses
        t.addrs = (t.server_name.as_str(), t.port)
            .to_socket_addrs()
            .map_err(|e| Error::ToSocketAddrs(e, t.server_name.clone()))?
            .collect();

        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, str::FromStr};

    use super::Target;

    #[test]
    fn new() {
        let ep = Target::new("8.8.8.8", 53).unwrap();
        assert_eq!(&ep.server_name, "8.8.8.8");
        assert_eq!(ep.port, 53);
        assert!(ep.addrs.contains(&SocketAddr::from_str("8.8.8.8:53").unwrap()));

        let ep = Target::new("a.root-servers.net", 53).unwrap();
        assert_eq!(&ep.server_name, "a.root-servers.net");
        assert_eq!(ep.port, 53);
        assert!(ep.addrs.contains(&SocketAddr::from_str("198.41.0.4:53").unwrap()));

        let ep = Target::new("https://cloudflare-dns.com/dns-query", 443).unwrap();
        assert_eq!(&ep.server_name, "https://cloudflare-dns.com/dns-query");
        assert_eq!(ep.port, 443);
        assert!(ep.addrs.is_empty());

        let ep = Target::new("https://2606:4700::6810:f9f9/dns-query", 443).unwrap();
        assert_eq!(&ep.server_name, "https://2606:4700::6810:f9f9/dns-query");
        assert_eq!(ep.port, 443);
        assert!(ep.addrs.is_empty());

        let ep = Target::new("quic://dns.adguard.com", 53).unwrap();
        assert_eq!(&ep.server_name, "dns.adguard.com");
        assert_eq!(ep.port, 53);
        assert!(ep.addrs.contains(&SocketAddr::from_str("94.140.15.15:53").unwrap()));
        assert!(ep.addrs.contains(&SocketAddr::from_str("94.140.14.14:53").unwrap()));

        let ep = Target::new("quic://94.140.15.15", 53).unwrap();
        assert_eq!(&ep.server_name, "94.140.15.15");
        assert_eq!(ep.port, 53);
        assert!(ep.addrs.contains(&SocketAddr::from_str("94.140.15.15:53").unwrap()));

        let ep = Target::new("1.1.1.1:853", 53).unwrap();
        assert_eq!(&ep.server_name, "1.1.1.1");
        assert_eq!(ep.port, 853);
        assert!(ep.addrs.contains(&SocketAddr::from_str("1.1.1.1:853").unwrap()));

        let ep = Target::new("[2606:4700:4700::1111]:853", 53).unwrap();
        assert_eq!(&ep.server_name, "2606:4700:4700::1111");
        assert_eq!(ep.port, 853);
        assert!(ep
            .addrs
            .contains(&SocketAddr::from_str("[2606:4700:4700::1111]:853").unwrap()));

        let ep = Target::new("[2606:4700:4700::1111]:853", 53).unwrap();
        assert_eq!(&ep.server_name, "2606:4700:4700::1111");
        assert_eq!(ep.port, 853);
        assert!(ep
            .addrs
            .contains(&SocketAddr::from_str("[2606:4700:4700::1111]:853").unwrap()));

        let ep = Target::new("one.one.one.one:853", 53).unwrap();
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
