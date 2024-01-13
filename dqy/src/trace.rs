use args::args::CliOptions;
use dns::rfc::qtype::QType;

use transport::{
    protocol::{IPVersion, Protocol},
    udp::UdpProtocol,
    Transporter,
};

// for the --trace optionflags
#[macro_use]
use lazy_static::lazy_static;
use log::{info, trace};
use rand::seq::IteratorRandom;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use crate::{build_query, receive_response, send_query};

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
fn get_random(version: &IPVersion) -> IpAddr {
    let mut rng = rand::thread_rng();
    let root = ROOT_SERVERS.keys().into_iter().choose(&mut rng).unwrap();
    info!("tracing: chosen root server: {}", root);

    if version == &IPVersion::V4 {
        IpAddr::from(ROOT_SERVERS[root].0)
    } else {
        IpAddr::from(ROOT_SERVERS[root].1)
    }
}

//───────────────────────────────────────────────────────────────────────────────────
// send query to ip address
//───────────────────────────────────────────────────────────────────────────────────
// fn send_query_to_ip(options: &CliOptions, qt: &QType, ipaddr: IpAddr) -> DNSResult<()> {
//     // build query
//     let query = build_query(options, qt)?;

//     // when need a SocketAddr to use it with any transport
//     let sockaddr = SocketAddr::from((ipaddr, options.transport.port));

//     // send query according to transport
//     match options.transport.transport_mode {
//         TransportMode::Udp => {
//             let mut udp_transport = UdpTransport::new(
//                 sockaddr,
//                 &options.transport.ip_version,
//                 options.transport.timeout,
//             )?;
//             send_receive_query(&options, &mut udp_transport)?;
//         }
//         TransportMode::Tcp => {
//             let mut tcp_transport = TcpTransport::new(
//                 options.protocol.resolvers.as_slice(),
//                 options.transport.timeout,
//             )?;
//             send_receive_query(&options, &mut tcp_transport)?;
//         }
//         TransportMode::DoT => {
//             // we need to initialize the TLS connexion using TCP stream and TLS features
//             let mut tls =
//                 TlsTransport::init_tls(&options.protocol.server, 853, options.transport.timeout)?;
//             let mut tls_transport = TlsTransport::new(&mut tls, options.transport.timeout)?;
//             // we need to initialize the TLS connexion using TCP stream and TLS features
//             send_receive_query(&options, &mut tls_transport)?;
//         }
//         TransportMode::DoH => {
//             let mut https_transport =
//                 HttpsTransport::new(&options.protocol.server, options.transport.timeout)?;
//             send_receive_query(&options, &mut https_transport)?;
//         }
//     }
//     Ok(())
// }

//───────────────────────────────────────────────────────────────────────────────────
// trace implementation
//
// explanation: https://superuser.com/questions/715632/how-does-dig-trace-actually-work
//
// ex: dig +trace www.google.co.uk.
//
// step1: chose a random root server
// step2: get its ip address (v4 or v6 depending on the cli options)
// setp3: get ip address of a random NS server: dig +norecurse @192.5.5.241 www.google.co.uk
//───────────────────────────────────────────────────────────────────────────────────
fn trace<T: Transporter>(options: &mut CliOptions, trp: &mut T) -> error::Result<()> {
    let mut buffer = [0u8; 4096];

    // set flag for no recursion desired to ge referral servers (no recursion)
    options.flags.recursion_desired = false;

    //───────────────────────────────────────────────────────────────────────────────────
    // step 1: get the ip address of a random root server
    //───────────────────────────────────────────────────────────────────────────────────
    let root_addr = get_random(&options.transport.ip_version);

    //───────────────────────────────────────────────────────────────────────────────────
    // step 2: get the NS address of a random name server for the considered domain
    //───────────────────────────────────────────────────────────────────────────────────

    Ok(())
}
