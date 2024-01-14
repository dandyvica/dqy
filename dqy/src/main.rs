//! A DNS resource query tool
//!
//! TODO: specialize RUST_LOG
use std::{process::ExitCode, time::Instant};

use log::{debug, error, info, trace};

// my DNS library
use dns::rfc::{
    domain::DomainName,
    opt::{
        dau_dhu_n3u::{EdnsKeyTag, DAU, DHU, N3U},
        nsid::NSID,
        opt::OPT,
        padding::Padding,
    },
    qtype::QType,
    query::{MetaRR, Query},
    response::Response,
    response_code::ResponseCode,
};

use args::args::{CliOptions, Display, Edns};
use error::Error;
use transport::{
    https::HttpsProtocol,
    protocol::{IPVersion, Protocol},
    tcp::TcpProtocol,
    tls::TlsProtocol,
    // transport,
    udp::UdpProtocol,
    Transporter,
};

// mod trace;
// use trace::*;

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

fn run() -> error::Result<()> {
    let now = Instant::now();

    // get arguments
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = CliOptions::options(&args)?;
    debug!("{:#?}", options);

    // trace test
    // if options.display.trace {
    //     println!("random={}", get_random(&IPVersion::V4));
    // }

    // let mut trp = transport(
    //     &options.transport.transport_mode,
    //     &options.transport.ip_version,
    //     options.transport.timeout,
    //     options.protocol.resolvers.as_slice(),
    // )?;
    // foo(&options, &mut trp);

    // depending on mode, different processing
    match options.transport.transport_mode {
        Protocol::Udp => {
            let mut udp_transport = UdpProtocol::new(
                options.protocol.resolvers.as_slice(),
                &options.transport.ip_version,
                options.transport.timeout,
            )?;
            send_receive_query(&options, &mut udp_transport)?;
        }
        Protocol::Tcp => {
            let mut tcp_transport = TcpProtocol::new(
                options.protocol.resolvers.as_slice(),
                options.transport.timeout,
            )?;
            send_receive_query(&options, &mut tcp_transport)?;
        }
        Protocol::DoT => {
            // we need to initialize the TLS connexion using TCP stream and TLS features
            let mut tls_transport =
                TlsProtocol::new(&options.protocol.server, options.transport.timeout)?;

            // we need to initialize the TLS connexion using TCP stream and TLS features
            send_receive_query(&options, &mut tls_transport)?;
        }
        Protocol::DoH => {
            let mut https_transport =
                HttpsProtocol::new(&options.protocol.server, options.transport.timeout, options.transport.https_version)?;
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

//───────────────────────────────────────────────────────────────────────────────────
// This sends and receive queries using a transport
//───────────────────────────────────────────────────────────────────────────────────
fn send_receive_query<T: Transporter>(options: &CliOptions, trp: &mut T) -> error::Result<()> {
    let mut buffer = [0u8; 4096];

    for qt in &options.protocol.qtype {
        // send query, response is depending on TC falg if UDP
        let query = send_query(options, qt, trp)?;
        let response = receive_response(trp, &mut buffer)?;

        // check for the truncation (TC) header flag. If set and UDP, resend using TCP
        if response.tc() && trp.mode() == Protocol::Udp {
            info!("query for {} caused truncation, resending using TCP", qt);
            let mut buffer = [0u8; 4096];

            let mut tcp_transport = TcpProtocol::new(
                &options.protocol.resolvers.as_slice(),
                options.transport.timeout,
            )?;
            let query = send_query(options, qt, &mut tcp_transport)?;
            let response = receive_response(&mut tcp_transport, &mut buffer)?;

            check_response_vs_query(&query, &response);
            display(&options.display, &query, &response);
            continue;
        }

        check_response_vs_query(&query, &response);
        // //println!("{}", serde_json::to_string(&response.question).unwrap());
        // response.show(ShowType::Color);
        display(&options.display, &query, &response);
    }

    Ok(())
}

//───────────────────────────────────────────────────────────────────────────────────
// build query from the cli options
//───────────────────────────────────────────────────────────────────────────────────
fn build_query<'a>(options: &'a CliOptions, qt: &QType) -> error::Result<Query<'a>> {
    //───────────────────────────────────────────────────────────────────────────────────
    // build the OPT record to be added in the additional section
    //───────────────────────────────────────────────────────────────────────────────────
    let opt = build_opt(options.transport.bufsize, &options.edns);
    trace!("OPT record: {:#?}", &opt);

    //───────────────────────────────────────────────────────────────────────────────────
    // build Query
    //───────────────────────────────────────────────────────────────────────────────────
    let domain = DomainName::try_from(options.protocol.domain.as_str())?;

    let mut query = Query::build()
        .with_type(qt)
        .with_class(&options.protocol.qclass)
        .with_domain(domain)
        .with_flags(&options.flags);

    //───────────────────────────────────────────────────────────────────────────────────
    // Reserve length if TCP or TLS
    //───────────────────────────────────────────────────────────────────────────────────
    if options.transport.transport_mode.uses_leading_length() {
        query = query.with_length();
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // Add OPT if any
    //───────────────────────────────────────────────────────────────────────────────────
    if let Some(opt) = opt {
        query = query.with_additional(MetaRR::OPT(opt));
    }
    trace!("Query record: {:#?}", &query);

    Ok(query)
}

//───────────────────────────────────────────────────────────────────────────────────
// build OPT RR from the cli options
//───────────────────────────────────────────────────────────────────────────────────
fn build_opt<'a>(bufsize: u16, edns: &Edns) -> Option<OPT> {
    // --no-opt
    if edns.no_opt {
        return None;
    }

    let mut opt = OPT::build(bufsize);

    //───────────────────────────────────────────────────────────────────────────────
    // add OPT options according to cli options
    //───────────────────────────────────────────────────────────────────────────────

    // NSID
    if edns.nsid {
        opt.add_option(NSID::default());
    }

    // padding
    if let Some(len) = edns.padding {
        opt.add_option(Padding::new(len));
    }

    // DAU, DHU & N3U
    if let Some(list) = &edns.dau {
        opt.add_option(DAU::from(list.as_slice()));
    }
    if let Some(list) = &edns.dhu {
        opt.add_option(DHU::from(list.as_slice()));
    }
    if let Some(list) = &edns.n3u {
        opt.add_option(N3U::from(list.as_slice()));
    }

    // edns-key-tag
    if let Some(list) = &edns.keytag {
        opt.add_option(EdnsKeyTag::from(list.as_slice()));
    }

    // dnssec flag ?
    if edns.dnssec {
        opt.set_dnssec();
    }

    Some(opt)
}

//───────────────────────────────────────────────────────────────────────────────────
// send the query to the resolver
//───────────────────────────────────────────────────────────────────────────────────
fn send_query<'a, T: Transporter>(
    options: &'a CliOptions,
    qt: &QType,
    trp: &mut T,
) -> error::Result<Query<'a>> {
    let mut query = build_query(options, qt)?;

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
) -> error::Result<Response<'a>> {
    let mut response = Response::default();
    let _ = response.recv(trp, buffer)?;

    Ok(response)
}

//───────────────────────────────────────────────────────────────────────────────────
// check if response corresponds to what the client sent
//───────────────────────────────────────────────────────────────────────────────────
fn check_response_vs_query<'a>(query: &Query<'a>, response: &Response<'a>) {
    if response.id() != query.header.id || query.question != response.question {
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

//───────────────────────────────────────────────────────────────────────────────────
// check if response corresponds to what the client sent
//───────────────────────────────────────────────────────────────────────────────────
fn display<'a>(display_options: &Display, query: &Query<'a>, response: &Response<'a>) {
    // JSON
    if display_options.json_pretty {
        let j = serde_json::json!({
            "query": query,
            "response": response
        });

        println!("{}", serde_json::to_string_pretty(&j).unwrap());
    } else if display_options.json {
        println!(
            "{}",
            serde_json::json!({
                "query": query,
                "response": response
            })
        );
    } else {
        if display_options.question {
            println!("{}", query);
        }
        println!("{}", response);
    }
}
