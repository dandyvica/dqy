//! A DNS resource query tool
use std::{process::ExitCode, time::Instant};

use log::{debug, info};

// internal modules
mod dns;
use dns::message::MessageList;

mod args;
use args::CliOptions;

mod error;
use error::Error;

mod network;
use network::{Messenger, Protocol};

mod show;
use show::{QueryInfo, ShowAll};

mod transport;
use transport::{https::HttpsProtocol, tcp::TcpProtocol, tls::TlsProtocol, udp::UdpProtocol};

mod trace;
use trace::*;

mod protocol;
use protocol::DnsProtocol;

mod options;

#[cfg(feature = "mlua")]
mod lua;
#[cfg(feature = "mlua")]
use lua::LuaDisplay;

// the initial length of the Vec buffer
const BUFFER_SIZE: usize = 4096;

//───────────────────────────────────────────────────────────────────────────────────
// Gather some information which might be useful for the user
//───────────────────────────────────────────────────────────────────────────────────
// #[derive(Debug, Default, Serialize)]
// pub struct Info {
//     //resolver reached
//     server: Option<SocketAddr>,

//     // elapsed time in ms
//     elapsed: u128,

//     // transport used (ex: Udp)
//     mode: String,

//     // bytes sent and received during network operations
//     bytes_sent: usize,
//     bytes_received: usize,
// }

// impl fmt::Display for Info {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         if let Some(peer) = self.server {
//             write!(f, "\nendpoint: {} ({})\n", peer, self.mode)?;
//         }
//         writeln!(f, "elapsed: {} ms", self.elapsed)?;
//         write!(
//             f,
//             "sent:{}, received:{} bytes",
//             self.bytes_sent, self.bytes_received
//         )
//     }
// }

//───────────────────────────────────────────────────────────────────────────────────
// get list of messages depending on transport
//───────────────────────────────────────────────────────────────────────────────────
fn get_messages_using_transport<T: Messenger>(
    info: Option<&mut QueryInfo>,
    transport: &mut T,
    options: &CliOptions,
) -> crate::error::Result<MessageList> {
    //info.server = transport.peer().ok();
    let messages = DnsProtocol::process_request(options, transport, BUFFER_SIZE)?;

    // we want info
    if let Some(info) = info {
        let stats = transport.netstat();

        info.bytes_sent = stats.0;
        info.bytes_received = stats.1;

        info.server = transport.peer().ok();
    }

    // let stats = transport.netstat();

    // info.bytes_sent = stats.0;
    // info.bytes_received = stats.1;

    Ok(messages)
}

pub fn get_messages(
    info: Option<&mut QueryInfo>,
    options: &CliOptions,
) -> crate::error::Result<MessageList> {
    info!(
        "qtype={:?} domain='{}' resolver=<{}>",
        options.protocol.qtype, options.protocol.domain_name, options.transport.endpoint
    );
    match options.transport.transport_mode {
        Protocol::Udp => {
            let mut transport = UdpProtocol::new(&options.transport)?;
            get_messages_using_transport(info, &mut transport, options)
        }
        Protocol::Tcp => {
            let mut transport = TcpProtocol::new(&options.transport)?;
            get_messages_using_transport(info, &mut transport, options)
        }
        Protocol::DoT => {
            let mut transport = TlsProtocol::new(&options.transport)?;
            get_messages_using_transport(info, &mut transport, options)
        }
        Protocol::DoH => {
            let mut transport = HttpsProtocol::new(&options.transport)?;
            get_messages_using_transport(info, &mut transport, options)
        }
        Protocol::DoQ => {
            unimplemented!("DoQ is not yet implemented")
        }
    }
}

//───────────────────────────────────────────────────────────────────────────────────
// use this trick to be able to display error
//───────────────────────────────────────────────────────────────────────────────────
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
            Error::IPParse(err) => {
                eprintln!("IP address parsing error (details: {err})");
                return ExitCode::from(3);
            }
            Error::Internal(err) => {
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
            #[cfg(feature = "mlua")]
            Error::Lua(err) => {
                eprintln!("Error calling Lua script (details: {:?})", err);
                return ExitCode::from(9);
            }
        }
    }

    ExitCode::SUCCESS
}

//───────────────────────────────────────────────────────────────────────────────────
// core of processing
//───────────────────────────────────────────────────────────────────────────────────
#[allow(unused_assignments)]
fn run() -> crate::error::Result<()> {
    let now = Instant::now();

    //───────────────────────────────────────────────────────────────────────────────────
    // get arguments
    //───────────────────────────────────────────────────────────────────────────────────
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut options = CliOptions::options(&args)?;
    debug!("{:#?}", options);

    //───────────────────────────────────────────────────────────────────────────────────
    // this will give user some information on how the protocol ran
    //───────────────────────────────────────────────────────────────────────────────────
    let mut info = QueryInfo::default();

    //───────────────────────────────────────────────────────────────────────────────────
    // trace if requested
    //───────────────────────────────────────────────────────────────────────────────────
    if options.display.trace {
        trace_resolution(&mut options)?;
        return Ok(());
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // send queries and receive responses
    //───────────────────────────────────────────────────────────────────────────────────
    let messages = get_messages(Some(&mut info), &options)?;

    //───────────────────────────────────────────────────────────────────────────────────
    // elapsed as millis will be hopefully enough
    //───────────────────────────────────────────────────────────────────────────────────
    let elapsed = now.elapsed();
    info.elapsed = elapsed.as_millis();

    // mode
    info.mode = options.transport.transport_mode.to_string();

    //───────────────────────────────────────────────────────────────────────────────────
    // final display to the user: either Lua code or Json or else
    //───────────────────────────────────────────────────────────────────────────────────
    #[cfg(feature = "mlua")]
    if let Some(lua_code) = options.display.lua_code {
        LuaDisplay::call_lua(messages, info, &lua_code)?;
        return Ok(());
    }

    // print out final results
    messages.show_all(&options.display, info);

    // DnsProtocol::display(&options.display, &info, &messages);
    Ok(())
}
