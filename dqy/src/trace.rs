use args::args::CliOptions;
use dns::rfc::qtype::QType;

use transport::{
    endpoint::EndPoint,
    protocol::{IPVersion, Protocol},
    udp::UdpProtocol,
    Transporter,
};

// for the --trace optionflags
#[macro_use]
use lazy_static::lazy_static;
use log::{debug, info, trace};
use rand::seq::IteratorRandom;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use crate::{get_messages, get_messages_using_transport, protocol::DnsProtocol, Info};

// use crate::{build_query, receive_response, send_query};

lazy_static! {
    // defined here: https://www.iana.org/domains/root/servers
    static ref ROOT_SERVERS: HashMap<&'static str, (Ipv4Addr, Ipv6Addr)> = {
        let mut m = HashMap::new();

        m.insert(
            "a.root-servers.net",
            (
                Ipv4Addr::from_str("198.41.0.4").unwrap(),
                Ipv6Addr::from_str("2001:503:ba3e::2:30").unwrap(),
            )
        );
        m.insert(
            "b.root-servers.net",
            (
                Ipv4Addr::from_str("170.247.170.2").unwrap(),
                Ipv6Addr::from_str("2801:1b8:10::b").unwrap(),
            )
        );
        m.insert(
            "c.root-servers.net",
            (
                Ipv4Addr::from_str("192.33.4.12").unwrap(),
                Ipv6Addr::from_str("2001:500:2::c").unwrap(),
            )
        );
        m.insert(
            "d.root-servers.net",
            (
                Ipv4Addr::from_str("199.7.91.13").unwrap(),
                Ipv6Addr::from_str("2001:500:2d::d").unwrap(),
            )
        );
        m.insert(
            "e.root-servers.net",
            (
                Ipv4Addr::from_str("192.203.230.10").unwrap(),
                Ipv6Addr::from_str("2001:500:a8::e").unwrap(),
            )
        );
        m.insert(
            "f.root-servers.net",
            (
                Ipv4Addr::from_str("192.5.5.241").unwrap(),
                Ipv6Addr::from_str("2001:500:2f::f").unwrap(),
            )
        );
        m.insert(
            "g.root-servers.net",
            (
                Ipv4Addr::from_str("192.112.36.4").unwrap(),
                Ipv6Addr::from_str("2001:500:12::d0d").unwrap(),
            )
        );
        m.insert(
            "h.root-servers.net",
            (
                Ipv4Addr::from_str("198.97.190.53").unwrap(),
                Ipv6Addr::from_str("2001:500:1::53").unwrap(),
            )
        );
        m.insert(
            "i.root-servers.net",
            (
                Ipv4Addr::from_str("192.36.148.17").unwrap(),
                Ipv6Addr::from_str("2001:7fe::53").unwrap(),
            )
        );
        m.insert(
            "j.root-servers.net",
            (
                Ipv4Addr::from_str("192.58.128.30").unwrap(),
                Ipv6Addr::from_str("2001:503:c27::2:30").unwrap(),
            )
        );
        m.insert(
            "k.root-servers.net",
            (
                Ipv4Addr::from_str("193.0.14.129").unwrap(),
                Ipv6Addr::from_str("2001:7fd::1").unwrap(),
            )
        );
        m.insert(
            "l.root-servers.net",
            (
                Ipv4Addr::from_str("199.7.83.42").unwrap(),
                Ipv6Addr::from_str("2001:500:9f::42").unwrap(),
            )
        );
        m.insert(
            "m.root-servers.net",
            (
                Ipv4Addr::from_str("202.12.27.33").unwrap(),
                Ipv6Addr::from_str("2001:dc3::35").unwrap(),
            )
        );

        m
    };
}

//───────────────────────────────────────────────────────────────────────────────────
// return a random root server ip address
//───────────────────────────────────────────────────────────────────────────────────
fn get_random_root(version: &IPVersion) -> IpAddr {
    let mut rng = rand::thread_rng();
    let root = ROOT_SERVERS.keys().into_iter().choose(&mut rng).unwrap();

    if version == &IPVersion::V4 {
        IpAddr::from(ROOT_SERVERS[root].0)
    } else {
        IpAddr::from(ROOT_SERVERS[root].1)
    }
}

//───────────────────────────────────────────────────────────────────────────────────
// send query to ip address
//───────────────────────────────────────────────────────────────────────────────────

//───────────────────────────────────────────────────────────────────────────────────
// trace implementation
//
// explanation: https://superuser.com/questions/715632/how-does-dig-trace-actually-work
//
// ex: dig +trace www.google.co.uk.
//
// step 1: chose a random root server
// step 2: get its ip address (v4 or v6 depending on the cli options)
// setp 3: get ip address of a random NS server: dig +norecurse @192.5.5.241 www.google.co.uk
//───────────────────────────────────────────────────────────────────────────────────
pub fn trace_resolution(opts: &CliOptions) -> error::Result<()> {
    let mut options = (*opts).clone();
    let mut info = Info::default();

    // shortcuts
    let port = opts.transport.port;
    let qt = options.protocol.qtype[0];

    // we only allow just one QType to query
    //debug_assert!(options.protocol.qtype.len() == 1);

    // need to save the asked QType because the first DNS message sent is NS

    // set flag for no recursion desired to get referral servers (no recursion)
    options.flags.recursion_desired = false;

    // we'll stop whenever an authorative answer is found
    let mut authorative = true;

    //───────────────────────────────────────────────────────────────────────────────────
    // step 1: get the ip address of a random root server
    //───────────────────────────────────────────────────────────────────────────────────
    let random_root_server = get_random_root(&options.transport.ip_version);
    info!("choosen random root server: {}", random_root_server);
    let endpoint = EndPoint::try_from((&random_root_server, port))?;
    options.transport.endpoint = endpoint;

    // while authorative {
    //     //───────────────────────────────────────────────────────────────────────────────────
    //     // step 1: get the ip address of a random root server
    //     //───────────────────────────────────────────────────────────────────────────────────
    //     let

    //     options.protocol.qtype = vec![QType::NS];
    //     options.protocol.domain = ".".to_string();

    //     //───────────────────────────────────────────────────────────────────────────────────
    //     // step 2: get the NS address of a random name server for the considered domain
    //     //───────────────────────────────────────────────────────────────────────────────────
    //     // options.transport.end_point = EndPoint::try_from((&root_addr, port))?;
    //     // let messages = get_messages(&options, &mut info)?;

    //     authorative = false;
    // }

    let messages = get_messages(&mut info, &options)?;
    DnsProtocol::display(&options.display, &info, &messages);

    Ok(())
}
