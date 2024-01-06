//! A DNS resource query tool
//!
//! TODO: specialize RUST_LOG
use std::{process::ExitCode, time::Instant};

use log::{debug, error, info, trace};

// my DNS library
use dns::{
    error::{DNSResult, Error},
    rfc::{
        opt::{opt::OptQuery, nsid::NSID, padding::Padding, dau_dhu_n3u::{DAU, DHU, N3U, EdnsKeyTag}}, qtype::QType, query::Query, response::Response,
        response_code::ResponseCode,
    },
    transport::{
        https::HttpsTransport, mode::TransportMode, tcp::TcpTransport, tls::TlsTransport,
        udp::UdpTransport, Transporter,
    },
};

use args::args::CliOptions;

// use this trick to be able to display error
fn main() -> ExitCode {
    let res = run();

    if let Err(e) = res {
        match e {
            Error::Io(err) => {
                eprintln!("I/O error (details: {err})");
                return ExitCode::from(1);
            }
            Error::Utf8(err) => {
                eprintln!("UTF8 conversion error (details: {err})");
                return ExitCode::from(2);
            }
            Error::AddrParseError(err) => {
                eprintln!("IP address parsing error (details: {err})");
                return ExitCode::from(3);
            }
            Error::InternalError(err) => {
                eprintln!("DNS protocol error (details: {err})");
                return ExitCode::from(4);
            }
            Error::Reqwest(err) => {
                eprintln!("DoH error (details: {err})");
                return ExitCode::from(5);
            }
            Error::Tls(err) => {
                eprintln!("DoT error (details: {err})");
                return ExitCode::from(6);
            }
            Error::Resolv(err) => {
                eprintln!("Fetching resolvers error (details: {:?})", err);
                return ExitCode::from(7);
            }
            Error::NoValidTCPConnection(a) => {
                if a.len() == 1 {
                    eprintln!("Timeout occured: couldn't TCP connect to: {:?}", a);
                } else {
                    eprintln!("Timeout occured: couldn't TCP connect to any of: {:?}", a);
                }
                return ExitCode::from(8);
            }
        }
    }

    ExitCode::SUCCESS
}

fn run() -> DNSResult<()> {
    let now = Instant::now();

    // get arguments
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = CliOptions::options(&args)?;
    debug!("{:#?}", options);

    // depending on mode, different processing
    match options.transport.transport_mode {
        TransportMode::Udp => {
            let mut udp_transport = UdpTransport::new(
                options.protocol.resolvers.as_slice(),
                &options.transport.ip_version,
                options.transport.timeout,
            )?;
            send_receive_query(&options, &mut udp_transport)?;
        }
        TransportMode::Tcp => {
            let mut tcp_transport =
                TcpTransport::new(options.protocol.resolvers.as_slice(), options.transport.timeout)?;
            send_receive_query(&options, &mut tcp_transport)?;
        }
        TransportMode::DoT => {
            // we need to initialize the TLS connexion using TCP stream and TLS features
            let mut tls = TlsTransport::init_tls(&options.protocol.server, 853, options.transport.timeout)?;
            let mut tls_transport = TlsTransport::new(&mut tls, options.transport.timeout)?;
            // we need to initialize the TLS connexion using TCP stream and TLS features
            send_receive_query(&options, &mut tls_transport)?;
        }
        TransportMode::DoH => {
            let mut https_transport = HttpsTransport::new(&options.protocol.server, options.transport.timeout)?;
            send_receive_query(&options, &mut https_transport)?;
        }
    }

    let elapsed = now.elapsed();
    if options.display.stats {
        eprintln!(
            "stats ==> server:{}, transport:{:?}, elapsed:{} ms",
            options.protocol.resolvers[0],
            options.transport.transport_mode,
            elapsed.as_millis()
        );
    }

    Ok(())
}

// This sends and receive queries using a transport
fn send_receive_query<T: Transporter>(options: &CliOptions, trp: &mut T) -> DNSResult<()> {
    let mut buffer = [0u8; 4096];

    for qt in &options.protocol.qtype {
        // send query, response is depending on TC falg if UDP
        let query = send_query(options, qt, trp)?;
        let response = receive_response(trp, &mut buffer)?;

        // check for the truncation (TC) header flag. If set and UDP, resend using TCP
        if response.header.flags.truncation && trp.mode() == TransportMode::Udp {
            info!("query for {} caused truncation, resending using TCP", qt);
            let mut buffer = [0u8; 4096];

            let mut tcp_transport =
                TcpTransport::new(&options.protocol.resolvers.as_slice(), options.transport.timeout)?;
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

//───────────────────────────────────────────────────────────────────────────────────
// send the query to the resolver
//───────────────────────────────────────────────────────────────────────────────────
fn send_query<'a, T: Transporter>(
    options: &'a CliOptions,
    qt: &QType,
    trp: &mut T,
) -> DNSResult<Query<'a>> {
    let mut query = Query::new(trp);
    query.init(&options.protocol.domain, qt, options.protocol.qclass)?;

    //───────────────────────────────────────────────────────────────────────────────────    
    // set flags if any
    //───────────────────────────────────────────────────────────────────────────────────    
    query.set_aa(options.flags.aaflag);
    query.set_ad(options.flags.adflag);
    query.set_cd(options.flags.cdflag);
    query.set_ra(options.flags.raflag);
    query.set_rd(options.flags.rdflag);
    query.set_tc(options.flags.tcflag);

    //───────────────────────────────────────────────────────────────────────────────────
    // manage edns options
    //───────────────────────────────────────────────────────────────────────────────────
    let mut opt = OptQuery::new(options.transport.bufsize);

    // NSID
    if options.edns.nsid {
        opt.add_option(NSID::default());
    }

    // padding
    if let Some(len) = options.edns.padding {
        opt.add_option(Padding::new(len));
    }

    // DAU, DHU & N3U
    if let Some(list) = &options.edns.dau {
        opt.add_option(DAU::from(list.as_slice()));
    }
    if let Some(list) = &options.edns.dhu {
        opt.add_option(DHU::from(list.as_slice()));
    }
    if let Some(list) = &options.edns.n3u {
        opt.add_option(N3U::from(list.as_slice()));
    }

    // edns-key-tag
    if let Some(list) = &options.edns.keytag {
        opt.add_option(EdnsKeyTag::from(list.as_slice()));
    }

    // dnssec flag ?
    if options.edns.dnssec {
        opt.set_dnssec();
    }

    // Add OPT record to the query
    trace!("OPT record: {:#?}", &opt);
    query.push_additional(opt);

    // send query using the chosen transport
    let bytes = query.send(trp)?;
    info!(
        "sent query of {} bytes to remote address {}",
        bytes,
        trp.peer()?
    );

    Ok(query)
}

//───────────────────────────────────────────────────────────────────────────────────
// receive response from resolver
//───────────────────────────────────────────────────────────────────────────────────
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
