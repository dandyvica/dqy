//! A DNS resource query tool
//! 
//! TODO: add trace for buffer in response
//! TODO: specialize RUST_LOG 
//! TODO: add DoH
use std::time::Instant;

use log::debug;

// my DNS library
use dns::{
    error::DNSResult,
    network::{tls::TlsConnexion, transport::Transport},
    rfc::{
        domain::DomainName, opt::OptQuery, qtype::QType, query::Query, resource_record::MetaRR,
        response::Response,
    },
};

use args::args::CliOptions;

fn main() -> DNSResult<()> {
    let now = Instant::now();

    env_logger::init();

    // get arguments
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let options = CliOptions::options(&mut args)?;
    debug!("{:?}", options);

    // if we use TLS (DoH or DoT), we need special handling for the TLS connexion
    if options.transport_mode.uses_tls() {
        let mut tls_conn = TlsConnexion::new("dns.google");
        let mut trp = Transport::new(
            &options.transport_mode,
            None,
            options.port,
            Some(&mut tls_conn),
        )?;
        trp.set_timeout(options.timeout)?;
        send_receive_query(&options, &mut trp)?;
    } else {
        let mut trp = Transport::new(
            &options.transport_mode,
            Some(&options.resolvers[0]),
            options.port,
            None,
        )?;
        trp.set_timeout(options.timeout)?;
        send_receive_query(&options, &mut trp)?;
    }

    let elapsed = now.elapsed();
    if options.stats {
        eprintln!(
            "stats ==> server:{}, transport:{:?}, elapsed:{} ms",
            options.resolvers[0],
            options.transport_mode,
            elapsed.as_millis()
        );
    }

    Ok(())
}

// This sends and receive queries using a transport
fn send_receive_query(options: &CliOptions, trp: &mut Transport) -> DNSResult<()> {
    let mut buffer = [0u8; 4096];

    for qt in &options.qtype {
        let mut query = Query::new(&options.transport_mode);
        query.init(&options.domain, qt, options.qclass)?;

        // manage edns options
        let mut opt = OptQuery::new(Some(1232));
        opt.set_edns_nsid();

        query.push_additional(opt);

        query.send(trp)?;

        let mut response = Response::new(&options.transport_mode);
        let bytes = response.recv(trp, &mut buffer)?;

        // check whether message ID is the one sent
        if response.header.id != query.header.id {
            eprintln!(
                "query and response ID are not equal, discarding answer for type {:?}",
                qt
            );
            continue;
        }

        //println!("{}", DisplayWrapper(&response));
        response.display();
    }

    Ok(())
}
