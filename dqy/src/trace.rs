use std::net::IpAddr;

use args::args::CliOptions;
use dns::rfc::{domain::DomainName, qtype::QType, response::ResponseCategory};

use serde_json::ser;
use transport::endpoint::EndPoint;

// for the --trace optionflags
use log::{info, trace};

use crate::{get_messages, get_messages_using_transport, protocol::DnsProtocol, Info};

//───────────────────────────────────────────────────────────────────────────────────
// send query to ip address
//───────────────────────────────────────────────────────────────────────────────────
pub fn resolve_ip(domain: &str, server_ip: Option<IpAddr>) -> error::Result<()> {
    // by default, endpoint is a random root server
    println!("=========> domain={}, server_ip={:?}", domain, server_ip);

    let mut options = CliOptions::default();

    // no recursion is mandatory for iterative query tracing
    options.flags.recursion_desired = false;

    options.protocol.qtype = vec![QType::A];
    options.protocol.domain_name = DomainName::try_from(domain)?;

    // if a server ip is provided, use it
    if let Some(ip) = server_ip {
        options.transport.endpoint = EndPoint::try_from((&ip, options.transport.port))?;
    }

    // now send query
    let messages = get_messages(None, &options)?;
    let resp = messages[0].response();
    println!("{}", resp);

    // in this case, a glue record with an ip address is found
    if let Some(rr) = resp.random_glue_record() {
        let ip = rr.ip_address();

        println!(
            "{} {:?} {}",
            rr.name,
            rr.ip_address(),
            options.flags.authorative_answer
        );

        if options.flags.authorative_answer {
            return Ok(());
        } else {
            resolve_ip(domain, ip)?
        }
    }
    // no glue record means no A or AAAA address for the NS records found.
    // so need to restart from root
    else {
        let rr = resp.random_ns_record();
        println!("{}", rr.unwrap());

        resolve_ip(&rr.unwrap().name.to_string(), None)?
    }

    Ok(())
}

pub fn find_ip(options: &mut CliOptions, domain: &str, server_ip: IpAddr) {
    println!("domain={}, ip={}", options.protocol.domain_name, server_ip);

    options.transport.endpoint = EndPoint::try_from((&server_ip, options.transport.port)).unwrap();

    // now send query
    let messages = get_messages(None, &options).unwrap();
    let resp = messages[0].response();
    println!("{}", resp);

    if let Some(rr) = resp.random_glue_record() {
        let name = &rr.name;
        let ip = rr.ip_address().unwrap();
        println!("domain: {}, ip: {} !!", name, ip);

        options.transport.endpoint = EndPoint::try_from((&ip, options.transport.port)).unwrap();
        let messages = get_messages(None, &options).unwrap();
        let resp = messages[0].response();
        println!("{}", resp);
    }
}

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
// pub fn trace_resolution(opts: &CliOptions) -> error::Result<()> {
//     let mut options = (*opts).clone();
//     let mut info = Info::default();

//     // shortcuts
//     //let port = opts.transport.port;
//     let qt = options.protocol.qtype[0];

//     // we only allow just one QType to query
//     //debug_assert!(options.protocol.qtype.len() == 1);

//     // need to save the asked QType because the first DNS message sent is NS

//     // set flag for no recursion desired to get referral servers (no recursion)
//     options.flags.recursion_desired = false;

//     // we'll stop whenever an authorative answer is found
//     let mut authorative = true;

//     trace!("tracing {}", qt);

//     //───────────────────────────────────────────────────────────────────────────────────
//     // step 1: get the ip address of a random root server
//     //───────────────────────────────────────────────────────────────────────────────────
//     let random_root_server = get_random_root(&options.transport.ip_version);
//     info!("choosen random root server: {}", random_root_server);
//     let endpoint = EndPoint::try_from((&random_root_server, opts.transport.port))?;
//     options.transport.endpoint = endpoint;

//     // while authorative {
//     //     //───────────────────────────────────────────────────────────────────────────────────
//     //     // step 1: get the ip address of a random root server
//     //     //───────────────────────────────────────────────────────────────────────────────────
//     //     let

//     //     options.protocol.qtype = vec![QType::NS];
//     //     options.protocol.domain = ".".to_string();

//     //     //───────────────────────────────────────────────────────────────────────────────────
//     //     // step 2: get the NS address of a random name server for the considered domain
//     //     //───────────────────────────────────────────────────────────────────────────────────
//     //     // options.transport.end_point = EndPoint::try_from((&root_addr, port))?;
//     //     // let messages = get_messages(&options, &mut info)?;

//     //     authorative = false;
//     // }

//     let messages = get_messages(&mut info, &options)?;
//     let resp = messages[0].response();
//     let rr = resp.random_rr(&qt, ResponseCategory::Additional);
//     println!("rr ==========> {}", rr.unwrap());

//     if let Some(rr) = rr {
//         let ip = rr.ip_address(&QType::A);
//         println!("ip ==========> {:?}", ip);

//         let endpoint = EndPoint::try_from((&ip.unwrap(), opts.transport.port))?;
//         options.transport.endpoint = endpoint;
//     }

//     DnsProtocol::display(&options.display, &info, &messages);

//     Ok(())
// }
