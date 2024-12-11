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
use crate::error::{Error, Network};

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
    pub fn new(server: &str, port: u16) -> Self {
        let mut t = Target::default();
        t.port = port;

        // 1st case: https://2606:4700::6810:f9f9/dns-query or @https://cloudflare-dns.com/dns-query
        if server.starts_with("https://") {
            t.server_name = server.to_string();
        }
        // 2nd case: @quic://dns.adguard.com or @quic://94.140.15.15
        else if server.starts_with("quic://") {
            let index = server.find("//").unwrap();
            t.server_name = server[index+2..].to_string();
        }
        // other cases
        else {
            // 3rd case: @1.1.1.1:53
            let re = Regex::new(r"([\d\.]+):(\d+)$").unwrap();
        }

        t
    }
}

