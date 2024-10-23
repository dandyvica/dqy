use lazy_static::lazy_static;
use rand::seq::IteratorRandom;

use crate::network::IPVersion;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

lazy_static! {
    // defined here: https://www.iana.org/domains/root/servers
    static ref ROOT_SERVERS: HashMap<&'static str, (Ipv4Addr, Ipv6Addr)> = {
        let mut m = HashMap::new();

        m.insert(
            "a.root-servers.net.",
            (
                Ipv4Addr::from_str("198.41.0.4").unwrap(),
                Ipv6Addr::from_str("2001:503:ba3e::2:30").unwrap(),
            )
        );
        m.insert(
            "b.root-servers.net.",
            (
                Ipv4Addr::from_str("170.247.170.2").unwrap(),
                Ipv6Addr::from_str("2801:1b8:10::b").unwrap(),
            )
        );
        m.insert(
            "c.root-servers.net.",
            (
                Ipv4Addr::from_str("192.33.4.12").unwrap(),
                Ipv6Addr::from_str("2001:500:2::c").unwrap(),
            )
        );
        m.insert(
            "d.root-servers.net.",
            (
                Ipv4Addr::from_str("199.7.91.13").unwrap(),
                Ipv6Addr::from_str("2001:500:2d::d").unwrap(),
            )
        );
        m.insert(
            "e.root-servers.net.",
            (
                Ipv4Addr::from_str("192.203.230.10").unwrap(),
                Ipv6Addr::from_str("2001:500:a8::e").unwrap(),
            )
        );
        m.insert(
            "f.root-servers.net.",
            (
                Ipv4Addr::from_str("192.5.5.241").unwrap(),
                Ipv6Addr::from_str("2001:500:2f::f").unwrap(),
            )
        );
        m.insert(
            "g.root-servers.net.",
            (
                Ipv4Addr::from_str("192.112.36.4").unwrap(),
                Ipv6Addr::from_str("2001:500:12::d0d").unwrap(),
            )
        );
        m.insert(
            "h.root-servers.net.",
            (
                Ipv4Addr::from_str("198.97.190.53").unwrap(),
                Ipv6Addr::from_str("2001:500:1::53").unwrap(),
            )
        );
        m.insert(
            "i.root-servers.net.",
            (
                Ipv4Addr::from_str("192.36.148.17").unwrap(),
                Ipv6Addr::from_str("2001:7fe::53").unwrap(),
            )
        );
        m.insert(
            "j.root-servers.net.",
            (
                Ipv4Addr::from_str("192.58.128.30").unwrap(),
                Ipv6Addr::from_str("2001:503:c27::2:30").unwrap(),
            )
        );
        m.insert(
            "k.root-servers.net.",
            (
                Ipv4Addr::from_str("193.0.14.129").unwrap(),
                Ipv6Addr::from_str("2001:7fd::1").unwrap(),
            )
        );
        m.insert(
            "l.root-servers.net.",
            (
                Ipv4Addr::from_str("199.7.83.42").unwrap(),
                Ipv6Addr::from_str("2001:500:9f::42").unwrap(),
            )
        );
        m.insert(
            "m.root-servers.net.",
            (
                Ipv4Addr::from_str("202.12.27.33").unwrap(),
                Ipv6Addr::from_str("2001:dc3::35").unwrap(),
            )
        );

        m
    };
}

//───────────────────────────────────────────────────────────────────────────────────
// return a random root server ip address for an IP version.
// if server is specified, we want this one.
//───────────────────────────────────────────────────────────────────────────────────
pub fn get_root_server(version: &IPVersion, server: Option<&str>) -> IpAddr {
    // we want a specific server ?
    let root = if let Some(server) = server {
        server
    } else {
        let mut rng = rand::thread_rng();
        ROOT_SERVERS.keys().choose(&mut rng).unwrap()
    };

    if version == &IPVersion::V4 || version == &IPVersion::Any {
        IpAddr::from(ROOT_SERVERS[root].0)
    } else {
        IpAddr::from(ROOT_SERVERS[root].1)
    }
}
