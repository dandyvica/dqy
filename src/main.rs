//! A DNS resource query
use std::io::Cursor;
use std::net::UdpSocket;

use log::debug;

// my DNS library
use dnslib::{
    error::DNSResult,
    network::Transport,
    rfc1035::{domain::DomainName, message::Message, qtype::QType},
};

mod resolver;

mod args;
use args::CliOptions;

mod display;
use display::DisplayWrapper;

const UDP_PORT: u16 = 53;

fn main() -> DNSResult<()> {
    env_logger::init();

    let mut buffer = [0u8; 512];

    // get arguments
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let options = CliOptions::options(&mut args)?;
    debug!("{:?}", options);
    println!("{:#?}", options);

    std::process::exit(1);

    let trp = Transport::new();

    //
    for qt in options.qtype {
        let mut query = Message::default();

        query.init(&options.domain, qt, options.qclass)?;
        query.send(&trp, &options.resolvers, UDP_PORT)?;

        let mut response = Message::default();
        let bytes = response.recv(&trp, &mut buffer)?;

        println!("{}", DisplayWrapper(&response));
    }

    Ok(())
}
