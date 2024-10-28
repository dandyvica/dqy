use std::fmt::Display;
use std::{fmt, net::SocketAddr};

use serde::Serialize;

//───────────────────────────────────────────────────────────────────────────────────
// Gather some information which might be useful for the user
//───────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default, Serialize)]
pub struct QueryInfo {
    //resolver reached
    pub server: Option<SocketAddr>,

    // elapsed time in ms
    pub elapsed: u128,

    // transport used (ex: Udp)
    pub mode: String,

    // bytes sent and received during network operations
    pub bytes_sent: usize,
    pub bytes_received: usize,
}

impl fmt::Display for QueryInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(peer) = self.server {
            write!(f, "\nendpoint: {} ({})\n", peer, self.mode)?;
        }
        writeln!(f, "elapsed: {} ms", self.elapsed)?;
        write!(
            f,
            "sent:{}, received:{} bytes",
            self.bytes_sent, self.bytes_received
        )
    }
}

//───────────────────────────────────────────────────────────────────────────────────
// Display options
//───────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default, Clone)]
pub struct ShowOptions {
    // print out stats like elasped time etc
    pub stats: bool,

    // iterative lookup
    pub trace: bool,

    // JSON output if true
    pub json: bool,
    pub json_pretty: bool,

    // true if we want the question in non-JSON print
    pub question: bool,

    // true if we only want the RDATA
    pub short: bool,

    // true if no additional section is printed out
    pub no_additional: bool,

    // true if no authorative section is printed out
    pub no_authorative: bool,

    // true if we want header for each section
    pub headers: bool,

    // show OPT record if any
    pub show_opt: bool,

    // formtting RRs
    pub fmt: String,

    // display TTL as seconds
    pub raw_ttl: bool,

    // align domain names
    pub align_names: bool,

    // content of the handlebars template file
    pub hb_tpl: Option<String>,

    // Lua code if specified
    #[cfg(feature = "mlua")]
    pub lua_code: Option<String>,
}

pub trait Show: Display {
    fn show(&self, display_options: &ShowOptions);
}
pub trait ShowAll: Display {
    fn show_all(&self, display_options: &ShowOptions, info: QueryInfo);
}

pub trait ToColor: Display {
    fn to_color(&self) -> colored::ColoredString;
}

// pub const NAME_COLOR: (u8, u8, u8) = (100, 100, 100);
