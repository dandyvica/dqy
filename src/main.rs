//! A DNS resource query tool
use std::{process::ExitCode, time::Instant};

// use handlebars::render;
use log::{debug, info};

// internal modules
mod dns;
use dns::message::MessageList;

mod args;
use args::CliOptions;

mod error;

mod show;
use show::{QueryInfo, ShowAll};

mod transport;
use transport::{
    https::HttpsProtocol,
    network::{Messenger, Protocol},
    quic::QuicProtocol,
    root_servers::init_root_map,
    tcp::TcpProtocol,
    tls::TlsProtocol,
    udp::UdpProtocol,
};

mod trace;
use trace::*;

mod protocol;
use protocol::DnsProtocol;

mod cli_options;

// mod handlebars;
// mod templating;

#[cfg(feature = "mlua")]
mod lua;
#[cfg(feature = "mlua")]
use lua::LuaDisplay;

// the initial length of the Vec buffer
const BUFFER_SIZE: usize = 8192;

//───────────────────────────────────────────────────────────────────────────────────
// get list of messages using transport
//───────────────────────────────────────────────────────────────────────────────────
fn get_messages_using_transport<T: Messenger>(
    info: Option<&mut QueryInfo>,
    transport: &mut T,
    options: &CliOptions,
) -> crate::error::Result<MessageList> {
    // BUFFER_SIZE is the size of the buffer used to received data
    let messages = DnsProtocol::process_request(options, transport, BUFFER_SIZE)?;

    // we want run info
    if let Some(info) = info {
        let stats = transport.netstat();

        info.bytes_sent = stats.0;
        info.bytes_received = stats.1;

        info.server = transport.peer().ok();
    }

    Ok(messages)
}

//───────────────────────────────────────────────────────────────────────────────────
// send all QTypes to domain and get responses for each query.
//───────────────────────────────────────────────────────────────────────────────────
pub fn get_messages(info: Option<&mut QueryInfo>, options: &CliOptions) -> crate::error::Result<MessageList> {
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
            // quinn crate doesn't provide blocking
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let result = rt.block_on(async {
                let mut transport = QuicProtocol::new(&options.transport).await.unwrap();
                let messages = DnsProtocol::async_process_request(options, &mut transport, BUFFER_SIZE)
                    .await
                    .unwrap();
                return messages;
            });

            Ok(result)
        }
    }
}

//───────────────────────────────────────────────────────────────────────────────────
// use this trick to be able to display error
//───────────────────────────────────────────────────────────────────────────────────
fn main() -> ExitCode {
    let res = run();

    if let Err(e) = res {
        eprintln!("{}", e);
        e.into()
    } else {
        ExitCode::SUCCESS
    }
}

//───────────────────────────────────────────────────────────────────────────────────
// core of processing
//───────────────────────────────────────────────────────────────────────────────────
#[allow(unused_assignments)]
fn run() -> crate::error::Result<()> {
    let now = Instant::now();

    init_root_map();

    //───────────────────────────────────────────────────────────────────────────────────
    // get arguments
    //───────────────────────────────────────────────────────────────────────────────────
    // skip program name
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut options = CliOptions::options(&args)?;
    info!("{:#?}", options);

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

    //───────────────────────────────────────────────────────────────────────────────────
    // print out final results
    //───────────────────────────────────────────────────────────────────────────────────
    // if let Some(tpl) = &options.display.hb_tpl {
    //     templating::render(&messages, &info, &tpl);
    // } else {
    //     messages.show_all(&options.display, info);
    // }
    messages.show_all(&options.display, info);

    Ok(())
}
