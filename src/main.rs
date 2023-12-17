//! A DNS resource query tool
//!
//! TODO: specialize RUST_LOG
use std::time::Instant;

use env_logger::{Builder, Env};
use log::{debug, error, info, trace};

// my DNS library
use dns::{
    error::DNSResult,
    rfc::{
        opt::opt::OptQuery, qtype::QType, query::Query, response::Response,
        response_code::ResponseCode,
    },
    transport::{
        https::HttpsTransport, mode::TransportMode, tcp::TcpTransport, tls::TlsTransport,
        udp::UdpTransport, Transporter,
    },
};

use args::args::CliOptions;

fn main() -> DNSResult<()> {
    let now = Instant::now();

    let env = Env::new().filter("DQY_LOG");
    env_logger::init_from_env(env);

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
    let mut buffer = [0u8; 4096];

    for qt in &options.qtype {
        // send query, response is depending on TC falg if UDP
        let query = send_query(options, qt, trp)?;
        let response = receive_response(trp, &mut buffer)?;

        // check for the truncation (TC) header flag. If set and UDP, resend using TCP
        if response.header.flags.truncated && trp.is_udp() {
            info!("query for {} caused truncation", qt);
            let mut buffer = [0u8; 4096];

            let mut tcp_transport =
                TcpTransport::new(&options.resolvers[0], options.port, options.timeout)?;
            let query = send_query(options, qt, &mut tcp_transport)?;
            let response = receive_response(&mut tcp_transport, &mut buffer)?;

            check_response_vs_query(&query, &response);
            println!("{}", response);
            continue;
        }

        check_response_vs_query(&query, &response);
        println!("{}", response);
    }

    Ok(())
}

// send the query to the resolver
fn send_query<'a, T: Transporter>(
    options: &'a CliOptions,
    qt: &QType,
    trp: &mut T,
) -> DNSResult<Query<'a>> {
    let mut query = Query::new(trp);
    query.init(&options.domain, qt, options.qclass)?;

    // manage edns options
    let mut opt = OptQuery::new(Some(1232));
    opt.set_edns_nsid();

    // dnssec flag ?
    if options.dnssec {
        opt.set_dnssec();
    }

    query.push_additional(opt);

    // send using the chosen transport
    let bytes = query.send(trp)?;
    trace!("sent query of {} bytes", bytes);

    Ok(query)
}

// receive response from resolver
fn receive_response<'a, T: Transporter>(
    trp: &mut T,
    buffer: &'a mut [u8],
) -> DNSResult<Response<'a>> {
    let mut response = Response::default();
    let _ = response.recv(trp, buffer)?;

    Ok(response)
}

// check if response corresponds to what the client sent
fn check_response_vs_query<'a>(query: &Query<'a>, response: &Response<'a>) {
    if response.header.id != query.header.id || query.question != response.question {
        error!(
            "query and response ID are not equal, discarding answer for type {:?}",
            query.question.qtype
        );
    }

    // check return code
    if response.rcode() != ResponseCode::NoError
        || (response.rcode() == ResponseCode::NXDomain && response.ns_count() == 0)
    {
        eprintln!("response error:{}", response.rcode());
    }
}
