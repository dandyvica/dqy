//! A DNS resource query
use std::io::Cursor;
use std::net::UdpSocket;
use std::process::exit;

use log::debug;

// my DNS library
use dnslib::{
    error::DNSResult,
    network::Transport,
    rfc1035::{domain::DomainName, message::Message, qtype::QType},
};

use args::args::CliOptions;

// mod display;
// use display::DisplayWrapper;

//mod output;

fn main() -> DNSResult<()> {
    env_logger::init();

    let mut buffer = [0u8; 512];

    // get arguments
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let options = CliOptions::options(&mut args)?;
    debug!("{:?}", options);

    let mut trp = Transport::new(&options.trp_type, options.resolvers[0], options.port)?;
    trp.set_timeout(options.timeout)?;

    //
    for qt in options.qtype {
        let mut query = Message::new(&options.trp_type);

        query.init(&options.domain, qt, options.qclass)?;
        query.send(&mut trp)?;

        let mut response = Message::new(&options.trp_type);
        let mut buffer = [0u8; 512];
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

    Ok(())
}
