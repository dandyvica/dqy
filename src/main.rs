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
    rfc::{opt::OptQuery, query::Query, response::Response},
    transport::{
        https::HttpsTransport, mode::TransportMode, tcp::TcpTransport, tls::TlsTransport,
        udp::UdpTransport, Transporter,
    },
};

use args::args::CliOptions;

fn main() -> DNSResult<()> {
    let now = Instant::now();

    env_logger::init();

    // get arguments
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = CliOptions::options(&args)?;
    debug!("{:?}", options);

    // depending on mode, different processing
    match options.transport_mode {
        TransportMode::Udp => {
            let mut udp_transport =
                UdpTransport::new(&options.resolvers[0], options.port, options.timeout)?;
            send_receive_query(&options, &mut udp_transport)?;
        }
        TransportMode::Tcp => {
            let mut tcp_transport =
                TcpTransport::new(&options.resolvers[0], options.port, options.timeout)?;
            send_receive_query(&options, &mut tcp_transport)?;
        }
        TransportMode::DoT => {
            // we need to initialize the TLS connexion using TCP stream and TLS features
            let mut tls = TlsTransport::init_tls(&options.server, 853)?;
            let mut tls_transport = TlsTransport::new(&mut tls, options.timeout)?;
            // we need to initialize the TLS connexion using TCP stream and TLS features
            send_receive_query(&options, &mut tls_transport)?;
        }
        TransportMode::DoH => {
            let mut https_transport = HttpsTransport::new(&options.server, options.timeout)?;
            send_receive_query(&options, &mut https_transport)?;

        }
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
fn send_receive_query<T: Transporter>(options: &CliOptions, trp: &mut T) -> DNSResult<()> {
    let mut recv_buf = [0u8; 4096];

    for qt in &options.qtype {
        //let mut query = Query::new(&options.transport_mode);
        let mut query = Query::new(trp);
        query.init(&options.domain, qt, options.qclass)?;

        // manage edns options
        let mut opt = OptQuery::new(Some(1232));
        opt.set_edns_nsid();

        query.push_additional(opt);

        query.send(trp)?;

        //let mut response = Response::new(&options.transport_mode);
        let mut response = Response::default();
        let _ = response.recv(trp, &mut recv_buf)?;

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
