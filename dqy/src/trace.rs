use args::args::CliOptions;
use dns::rfc::{domain::ROOT, qtype::QType};

use error::{Error, ProtocolError};
use transport::{endpoint::EndPoint, root_servers::get_root_server};

use crate::get_messages;

pub fn trace_resolution(options: &mut CliOptions) -> error::Result<()> {
    // save original options
    let qt = options.protocol.qtype[0];
    let dom = options.protocol.domain_name.clone();
    let ep = options.transport.endpoint.clone();

    // no recursion wanted
    options.flags.recursion_desired = false;

    // send NS . to my DNS to get list of root servers
    options.protocol.qtype = vec![QType::NS];
    options.protocol.domain_name = ROOT;
    let messages = get_messages(None, options)?;
    let resp = messages[0].response();
    println!("{}", resp);

    // chose a random root server
    let mut ip = get_root_server(&options.transport.ip_version, None);
    options.protocol.qtype = vec![qt];

    // reset the original domain to query
    options.protocol.domain_name = dom.clone();

    loop {
        options.transport.endpoint = EndPoint::try_from((&ip, options.transport.port))?;

        let messages = get_messages(None, options)?;
        let resp = messages[0].response();
        println!("{}", resp);

        // did we find the ip address for the domain we asked for ?
        if let Some(ip) = resp.ip_address(&qt, &options.protocol.domain_name) {
            println!("!!! found ip={}", ip);
            return Ok(());
        }

        // no, so continue. If glue records, this means we have addresses
        if let Some(rr) = resp.random_glue_record(&qt) {
            ip = rr
                .ip_address()
                .ok_or(Error::InternalError(ProtocolError::ErrorDuringTracing))?;
        } else {
            // query regular resolver for resolving random ns server in the auth section
            let rr = resp
                .random_ns_record()
                .ok_or(Error::InternalError(ProtocolError::ErrorDuringTracing))?;

            options.transport.endpoint = ep.clone();
            options.protocol.domain_name = rr
                .ns_name()
                .ok_or(Error::InternalError(ProtocolError::ErrorDuringTracing))?;

            let messages = get_messages(None, options)?;
            let resp = messages[0].response();
            println!("{:#?}", resp);

            // find the ip address
            ip = resp
                .ip_address(&qt, &options.protocol.domain_name)
                .ok_or(Error::InternalError(ProtocolError::ErrorDuringTracing))?;

            // reset to the original domain we're looking for
            options.protocol.domain_name = dom.clone();
        }
    }
}
