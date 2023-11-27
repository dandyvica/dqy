//! A DNS resource query tool
use std::time::Instant;

use log::debug;

// my DNS library
use dns::{
    error::DNSResult,
    network::Transport,
    rfc::{
        domain::DomainName, qtype::QType, query::Query, resource_record::MetaRR, response::Response, opt::OPTRR
    },
};

use args::args::CliOptions;

// mod display;
// use display::DisplayWrapper;

//mod output;

fn main() -> DNSResult<()> {
    let now = Instant::now();

    env_logger::init();

    let mut buffer = [0u8; 4096];

    // get arguments
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let options = CliOptions::options(&mut args)?;
    debug!("{:?}", options);

    let mut trp = Transport::new(&options.trp_type, options.resolvers[0], options.port)?;
    trp.set_timeout(options.timeout)?;

    //
    for qt in options.qtype {
        let mut query = Query::new(&options.trp_type);
        query.init(&options.domain, qt, options.qclass)?;

        // manage edns options
        // let mut opt = MetaRR::new_opt(None);
        // opt.rd_length = opt.set_edns_nsid()? as u16;
        let mut opt = OPTRR::new(Some(20));
        opt.set_edns_nsid()?;

        query.push_additional(opt.0);

        query.send(&mut trp)?;

        let mut response = Response::new(&options.trp_type);
        //let mut buffer = [0u8; 512];
        let bytes = response.recv(&mut trp, &mut buffer)?;

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

    let elapsed = now.elapsed();
    if options.stats {
        eprintln!(
            "stats ==> server:{}, transport:{:?}, elapsed:{} ms",
            options.resolvers[0],
            options.trp_type,
            elapsed.as_millis()
        );
    }

    Ok(())
}
