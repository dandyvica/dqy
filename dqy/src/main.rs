//! A DNS resource query tool
//!
//! TODO: specialize RUST_LOG
use std::{process::ExitCode, time::Instant};

use log::debug;

// my DNS library
use dns::rfc::message::MessageList;

use args::args::CliOptions;
use error::Error;
use show::Show;
use transport::{
    https::HttpsProtocol, protocol::Protocol, tcp::TcpProtocol, tls::TlsProtocol, udp::UdpProtocol,
};

// mod trace;
// use trace::*;

mod protocol;
use protocol::DnsProtocol;

//
const BUFFER_CHUNK: usize = 4096;

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
    // match options.transport.transport_mode {
    //     Protocol::Udp => {
    //         let mut udp_transport = UdpProtocol::new(&options.transport)?;
    //         DnsProtocol::send_receive(&options, &mut udp_transport)?;
    //     }
    //     Protocol::Tcp => {
    //         let mut tcp_transport = TcpProtocol::new(&options.transport)?;
    //         DnsProtocol::send_receive(&options, &mut tcp_transport)?;
    //     }
    //     Protocol::DoT => {
    //         // we need to initialize the TLS connexion using TCP stream and TLS features
    //         let mut tls_transport = TlsProtocol::new(&options.transport)?;

    //         // we need to initialize the TLS connexion using TCP stream and TLS features
    //         DnsProtocol::send_receive(&options, &mut tls_transport)?;
    //     }
    //     Protocol::DoH => {
    //         let mut https_transport = HttpsProtocol::new(&options.transport)?;
    //         DnsProtocol::send_receive(&options, &mut https_transport)?;
    //     }
    // }

    let messages = match options.transport.transport_mode {
        Protocol::Udp => {
            let mut udp_transport = UdpProtocol::new(&options.transport)?;
            DnsProtocol::send_receive(&options, &mut udp_transport, BUFFER_CHUNK)?
        }
        Protocol::Tcp => {
            let mut tcp_transport = TcpProtocol::new(&options.transport)?;
            DnsProtocol::send_receive(&options, &mut tcp_transport, BUFFER_CHUNK)?
        }
        Protocol::DoT => {
            // we need to initialize the TLS connexion using TCP stream and TLS features
            let mut tls_transport = TlsProtocol::new(&options.transport)?;

            // we need to initialize the TLS connexion using TCP stream and TLS features
            DnsProtocol::send_receive(&options, &mut tls_transport, BUFFER_CHUNK)?
        }
        Protocol::DoH => {
            let mut https_transport = HttpsProtocol::new(&options.transport)?;
            DnsProtocol::send_receive(&options, &mut https_transport, BUFFER_CHUNK)?
        }
    };

    let elapsed = now.elapsed();
    if options.display.stats {
        eprintln!(
            "stats ==> server:{}, transport:{:?}, elapsed:{} ms",
            options.protocol.resolvers[0],
            options.transport.transport_mode,
            elapsed.as_millis()
        );
    }

    display(&options.display, &messages);

    Ok(())
}

fn display(display_options: &show::DisplayOptions, messages: &MessageList) {
    // JSON
    if display_options.json_pretty {
        println!("fooo {}", serde_json::to_string_pretty(messages).unwrap());
    } else if display_options.json {
        println!("{}", serde_json::to_string(messages).unwrap());
    } else {
        // if display_options.question {
        //     println!("{:?}", msg_list.query);
        // }
        for msg in messages.iter() {
            msg.response().show(display_options);
        }
    }
}
