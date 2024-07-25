//! A DNS resource query tool
use std::{fmt, net::SocketAddr, process::ExitCode, time::Instant};

use dns::rfc::message::MessageList;
use log::debug;
use serde::Serialize;

use args::args::CliOptions;
use error::Error;
use transport::{
    https::HttpsProtocol, protocol::Protocol, tcp::TcpProtocol, tls::TlsProtocol, udp::UdpProtocol,
    TransportOptions, Transporter,
};

mod trace;
use trace::*;

mod protocol;
use protocol::DnsProtocol;

#[cfg(not(feature = "nolua"))]
mod lua;
#[cfg(not(feature = "nolua"))]
use lua::LuaDisplay;

// the initial length of the Vec buffer
const BUFFER_CHUNK: usize = 4096;

//───────────────────────────────────────────────────────────────────────────────────
// Gather some information which might be useful for the user
//───────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default, Serialize)]
struct Info {
    server: Option<SocketAddr>,
    elapsed: u128,
    mode: String,
    bytes_sent: usize,
    bytes_received: usize,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(peer) = self.server {
            write!(f, "\nendpoint: {} ({})\n", peer, self.mode)?;
        }
        write!(f, "elapsed: {} ms\n", self.elapsed)?;
        write!(
            f,
            "sent:{}, received:{} bytes",
            self.bytes_sent, self.bytes_received
        )
    }
}

// get list of messages depending on transport
fn get_messages_using_transport<T: Transporter>(
    info: &mut Info,
    transport: &mut T,
    options: &CliOptions,
) -> error::Result<MessageList> {
    info.server = transport.peer().ok();
    let messages = DnsProtocol::send_receive(&options, transport, BUFFER_CHUNK)?;

    let stats = transport.netstat();

    info.bytes_sent = stats.0;
    info.bytes_received = stats.1;

    Ok(messages)
}

pub fn get_messages(info: &mut Info, options: &CliOptions) -> error::Result<MessageList> {
    match options.transport.transport_mode {
        Protocol::Udp => {
            let mut transport = UdpProtocol::new(&options.transport)?;
            get_messages_using_transport(info, &mut transport, &options)
        }
        Protocol::Tcp => {
            let mut transport = TcpProtocol::new(&options.transport)?;
            get_messages_using_transport(info, &mut transport, &options)
        }
        Protocol::DoT => {
            let mut transport = TlsProtocol::new(&options.transport)?;
            get_messages_using_transport(info, &mut transport, &options)
        }
        Protocol::DoH => {
            let mut transport = HttpsProtocol::new(&options.transport)?;
            get_messages_using_transport(info, &mut transport, &options)
        }
        Protocol::DoQ => {
            unimplemented!("DoQ is not yet implemented")
        }
    }
}

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
            Error::Lua(err) => {
                eprintln!("Error calling Lua script (details: {:?})", err);
                return ExitCode::from(9);
            }
        }
    }

    ExitCode::SUCCESS
}

#[allow(unused_assignments)]
fn run() -> error::Result<()> {
    let now = Instant::now();

    // get arguments
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = CliOptions::options(&args)?;
    debug!("{:#?}", options);

    // this will give user some information on how the protocol ran
    let mut info = Info::default();

    // trace test
    if options.display.trace {
        let _ = trace_resolution(&options);
        std::process::exit(0);
    }

    let messages = match options.transport.transport_mode {
        Protocol::Udp => {
            let mut transport = UdpProtocol::new(&options.transport)?;
            get_messages_using_transport(&mut info, &mut transport, &options)?
            // info.server = transport.peer().ok();
            // let messages = DnsProtocol::send_receive(&options, &mut transport, BUFFER_CHUNK)?;

            // info.bytes_sent = transport.netstat.0;
            // info.bytes_received = transport.netstat.1;

            // messages
        }
        Protocol::Tcp => {
            let mut transport = TcpProtocol::new(&options.transport)?;
            get_messages_using_transport(&mut info, &mut transport, &options)?
            // info.server = transport.peer().ok();
            // let messages = DnsProtocol::send_receive(&options, &mut transport, BUFFER_CHUNK)?;

            // info.bytes_sent = transport.netstat.0;
            // info.bytes_received = transport.netstat.1;

            // messages
        }
        Protocol::DoT => {
            let mut transport = TlsProtocol::new(&options.transport)?;
            get_messages_using_transport(&mut info, &mut transport, &options)?
            // info.server = transport.peer().ok();
            // let messages = DnsProtocol::send_receive(&options, &mut transport, BUFFER_CHUNK)?;

            // info.bytes_sent = transport.netstat.0;
            // info.bytes_received = transport.netstat.1;

            // messages
        }
        Protocol::DoH => {
            let mut transport = HttpsProtocol::new(&options.transport)?;
            get_messages_using_transport(&mut info, &mut transport, &options)?
            // let messages = DnsProtocol::send_receive(&options, &mut transport, BUFFER_CHUNK)?;
            // info.server = transport.peer().ok();

            // info.bytes_sent = transport.stats.0;
            // info.bytes_received = transport.stats.1;

            // messages
        }
        Protocol::DoQ => {
            unimplemented!("DoQ is not yet implemented")
        }
    };

    // elapsed as millis will be hopefully enough
    let elapsed = now.elapsed();
    info.elapsed = elapsed.as_millis();

    // mode
    info.mode = options.transport.transport_mode.to_string();

    //───────────────────────────────────────────────────────────────────────────────────
    // final display to the user: either Lua code or Json or else
    //───────────────────────────────────────────────────────────────────────────────────
    #[cfg(not(feature = "nolua"))]
    if let Some(lua_code) = options.display.lua_code {
        LuaDisplay::call_lua(messages, info, &lua_code)?;
        return Ok(());
    }

    DnsProtocol::display(&options.display, &info, &messages);
    Ok(())
}
