use std::fmt;
use std::fmt::Display;
use std::path::PathBuf;

use serde::Serialize;

use crate::transport::NetworkInfo;

//───────────────────────────────────────────────────────────────────────────────────
// Gather some information which might be useful for the user
//───────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default, Serialize)]
pub struct QueryInfo {
    // elapsed time in ms
    pub elapsed: u128,

    // transport used (ex: Udp)
    pub mode: String,

    // network info gathered during network operations
    pub netinfo: NetworkInfo,
}

impl fmt::Display for QueryInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(peer) = self.netinfo.peer {
            write!(f, "\nendpoint: {} ({})\n", peer, self.mode)?;
        }
        writeln!(f, "elapsed: {} ms", self.elapsed)?;
        write!(
            f,
            "sent:{}, received:{} bytes",
            self.netinfo.sent, self.netinfo.received
        )
    }
}

//───────────────────────────────────────────────────────────────────────────────────
// Display options
//───────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default, Clone)]
pub struct DisplayOptions {
    // print out stats like elasped time etc
    pub stats: bool,

    // iterative lookup
    pub trace: bool,

    // JSON output if true
    pub json: bool,
    pub json_pretty: bool,

    // true if we want the question in non-JSON print
    pub show_question: bool,

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

    // print out punnycode values instead of UTF-8
    pub puny: bool,

    // show all information possible
    pub show_all: bool,

    // Lua code if specified
    #[cfg(feature = "mlua")]
    pub lua_code: Option<String>,
}

//───────────────────────────────────────────────────────────────────────────────────
// Dump options
//───────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default, Clone)]
pub struct DumpOptions {
    // optional file containing Query raw data to save
    pub write_query: Option<PathBuf>,

    // optional file containing Query raw data to read
    pub write_response: Option<PathBuf>,
}

pub trait Show: Display {
    fn show(&self, display_options: &DisplayOptions, length: Option<usize>);
}
pub trait ShowAll: Display {
    fn show_all(&self, display_options: &DisplayOptions, info: QueryInfo);
}

pub trait ToColor: Display {
    fn to_color(&self) -> colored::ColoredString;
}

// pub const NAME_COLOR: (u8, u8, u8) = (100, 100, 100);

// titles when displaying headers: build a map giving for each title its colored version
use colored::*;
use std::collections::HashMap;
use std::sync::LazyLock;

type ColoredTitles = HashMap<String, ColoredString>;

pub static TITLES: LazyLock<ColoredTitles> = LazyLock::new(|| {
    const COLOR: Color = Color::BrightCyan;

    // local helper
    fn insert_title(h: &mut ColoredTitles, title: &str, color: Color) {
        h.insert(title.to_string(), title.color(color));
    }

    // init new hmap
    let mut h = HashMap::new();

    // add all titles
    insert_title(&mut h, "qname", COLOR);
    insert_title(&mut h, "qtype", COLOR);
    insert_title(&mut h, "qclass", COLOR);
    insert_title(&mut h, "name", COLOR);
    insert_title(&mut h, "type", COLOR);
    insert_title(&mut h, "payload", COLOR);
    insert_title(&mut h, "rcode", COLOR);
    insert_title(&mut h, "version", COLOR);
    insert_title(&mut h, "flags", COLOR);

    h
});

pub fn header_section(text: &str, length: Option<usize>) -> ColoredString {
    let s = if let Some(l) = length {
        format!("{:<l$}", text)
    } else {
        format!("{}", text)
    };
    s.black().on_bright_cyan()
}
