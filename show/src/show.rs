use std::fmt::Display;

use crate::query_info::QueryInfo;

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

    // Lua code if specified
    #[cfg(feature = "lua")]
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
