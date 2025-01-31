use log::trace;

use dnslib::dns::rfc::domain::ROOT;
use dnslib::dns::rfc::{domain::ROOT_DOMAIN, qtype::QType};
use dnslib::error::*;
use dnslib::transport::{endpoint::EndPoint, root_servers::get_root_server};

use crate::args::CliOptions;
use crate::get_messages;
use crate::show::Show;

pub fn trace_resolution(options: &mut CliOptions) -> dnslib::error::Result<()> {
    trace!("tracing started");

    // save original options
    let orig_qt = options.protocol.qtype[0];
    let orig_domain = options.protocol.domain_name.clone();
    let orig_ep = options.transport.endpoint.clone();

    // no recursion wanted
    options.flags.recursion_desired = true;

    // send NS . to my DNS to get list of root servers
    trace!("query:{} domain:{} server:{}", QType::NS, ROOT, orig_ep);
    options.protocol.qtype = vec![QType::NS];
    options.protocol.domain_name = ROOT_DOMAIN;
    let messages = get_messages(None, options)?;
    let resp = messages[0].response();
    resp.show(&options.display, None);
    println!();

    // chose a random root server
    let mut ip = get_root_server(&options.transport.ip_version, None);
    options.protocol.qtype = vec![orig_qt];

    // reset the original domain to query
    options.protocol.domain_name = orig_domain.clone();

    loop {
        // iterative query => RD = false
        options.flags.recursion_desired = false;

        options.transport.endpoint = EndPoint::try_from((&ip, options.transport.port))?;
        trace!(
            "query:{} domain:{} server:{}",
            orig_qt,
            orig_domain,
            options.transport.endpoint
        );

        let messages = get_messages(None, options)?;
        let resp = messages[0].response();
        resp.show(&options.display, None);
        println!();

        // did we find the ip address for the domain we asked for ?
        if let Some(_ip) = resp.ip_address(&orig_qt, &options.protocol.domain_name) {
            // println!("!!! found ip={}", ip);
            return Ok(());
        }

        // no, so continue. If glue records, this means we have addresses
        if let Some(rr) = resp.random_glue_record(&orig_qt) {
            ip = rr.ip_address().ok_or(Error::Dns(Dns::ImpossibleToTrace))?;
        } else {
            // query regular resolver for resolving random ns server in the auth section
            let rr = resp.random_ns_record().ok_or(Error::Dns(Dns::ImpossibleToTrace))?;

            options.flags.recursion_desired = true;

            options.transport.endpoint = orig_ep.clone();
            options.protocol.domain_name = rr.ns_name().ok_or(Error::Dns(Dns::ImpossibleToTrace))?;

            trace!(
                "query:{} domain:{} server:{}",
                orig_qt,
                orig_domain,
                options.transport.endpoint
            );
            let messages = get_messages(None, options)?;
            let resp = messages[0].response();
            resp.show(&options.display, None);

            // find the ip address
            ip = resp
                .ip_address(&orig_qt, &options.protocol.domain_name)
                .ok_or(Error::Dns(Dns::ImpossibleToTrace))?;

            // reset to the original domain we're looking for
            options.protocol.domain_name = orig_domain.clone();
        }
    }
}
