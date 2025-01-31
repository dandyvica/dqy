use std::fmt;
use std::fmt::Display;
use std::path::PathBuf;

use colored::Colorize;
use dnslib::dns::rfc::domain::DomainName;
use dnslib::dns::rfc::query::Query;
use dnslib::dns::rfc::response::Response;
use dnslib::dns::rfc::rrlist::RRList;
use dnslib::header_section;
use serde::Serialize;

use dnslib::dns::message::{Message, MessageList};
use dnslib::dns::rfc::qtype::QType;
use dnslib::dns::rfc::rdata::RData;
use dnslib::dns::rfc::resource_record::{ResourceRecord, Ttl};
use dnslib::transport::NetworkInfo;

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
            writeln!(f, "endpoint: {} ({})", peer, self.mode)?;
        }
        writeln!(f, "elapsed: {} ms", self.elapsed)?;
        writeln!(
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
    pub show_headers: bool,

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

    // show response header
    pub sho_resp_header: bool,

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

impl Show for Response {
    fn show(&self, display_options: &DisplayOptions, max_length: Option<usize>) {
        // const HEADER_LENGTH: usize = 80;

        //───────────────────────────────────────────────────────────────────────────────────
        // Response HEADER
        //───────────────────────────────────────────────────────────────────────────────────
        if display_options.sho_resp_header {
            println!("{}", header_section("Response HEADER", None));
            println!("{}\n", self.header);
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // ANSWER
        //───────────────────────────────────────────────────────────────────────────────────
        if self.header.an_count > 0 {
            debug_assert!(self.answer.is_some());

            if display_options.show_headers {
                println!("{}", header_section("ANSWER", None));
            }
            self.answer.as_ref().unwrap().show(display_options, max_length);
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // AUTHORATIVE
        //───────────────────────────────────────────────────────────────────────────────────
        if self.header.ns_count > 0 && display_options.show_all {
            debug_assert!(self.authority().is_some());

            if display_options.show_headers {
                println!("\n{}", header_section("AUTHORATIVE", None));
            }
            self.authority().as_ref().unwrap().show(display_options, max_length);
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // ADDITIONAL
        //───────────────────────────────────────────────────────────────────────────────────
        if self.header.ar_count > 0 && display_options.show_all {
            debug_assert!(self.additional().is_some());

            if display_options.show_headers {
                println!("\n{}", header_section("ADDITIONAL", None));
            }
            self.additional().as_ref().unwrap().show(display_options, max_length);
        }
    }
}

impl Show for RRList {
    fn show(&self, display_options: &DisplayOptions, _: Option<usize>) {
        let max_length = if display_options.align_names {
            self.max_length()
        } else {
            None
        };

        for rr in self.iter() {
            // don't display OPT if not requested
            // if rr.r#type == QType::OPT && !display_options.show_opt {
            //     continue;
            // } else {
            //     rr.show(display_options, max_length);
            // }
            rr.show(display_options, max_length);
        }
    }
}

impl Show for Query {
    fn show(&self, display_options: &DisplayOptions, _length: Option<usize>) {
        // print out Query if requested
        if display_options.show_question {
            println!("{}", self);
        }
    }
}

impl Show for Message {
    fn show(&self, display_options: &DisplayOptions, length: Option<usize>) {
        // print out Query if requested
        if display_options.show_question {
            self.query.show(display_options, length);
        }

        self.response.show(display_options, length);
    }
}

// standard lengths for displaying and aligning a RR
const NAME_DISPLAY_LENGTH: usize = 28;
const TYPE_DISPLAY_LENGTH: usize = 10;
const LENGTH_DISPLAY_LENGTH: usize = 5;
const CLASS_DISPLAY_LENGTH: usize = 4;
const TTL_INT_DISPLAY_LENGTH: usize = 7;
const TTL_STRING_DISPLAY_LENGTH: usize = 12;
const PAYLOAD_DISPLAY_LENGTH: usize = 5;
const EXTCODE_DISPLAY_LENGTH: usize = 5;
const VERSION_DISPLAY_LENGTH: usize = 5;
const FLAGS_DISPLAY_LENGTH: usize = 5;

fn display(rr: &ResourceRecord, fmt: &str, raw_ttl: bool, name_length: usize, puny: bool) {
    for f in fmt.split(",") {
        match f.trim() {
            // except OPT
            "name" => {
                // print punycodes
                if puny {
                    print!("{:<name_length$} ", rr.name.to_color());
                }
                // print as UTF-8
                else {
                    // convert domain name back to UTF-8
                    if rr.name.is_puny() {
                        let unicode = rr.name.to_unicode().unwrap();
                        print!("{:<name_length$}", unicode.bright_green());
                    }
                    // not puny-like
                    else {
                        print!("{:<name_length$} ", rr.name.to_color());
                    }
                }
            }
            "type" => print!("{:<TYPE_DISPLAY_LENGTH$} ", rr.r#type.to_color()),
            "length" => print!("{:<LENGTH_DISPLAY_LENGTH$} ", rr.rd_length()),
            "class" => {
                if let Some(r) = rr.opt_or_class_ttl.regular() {
                    print!("{:<CLASS_DISPLAY_LENGTH$} ", r.class().to_string())
                }
            }
            "ttl" => {
                if let Some(r) = rr.opt_or_class_ttl.regular() {
                    if raw_ttl {
                        print!("{:<TTL_INT_DISPLAY_LENGTH$} ", r.ttl())
                    } else {
                        print!("{:<TTL_STRING_DISPLAY_LENGTH$} ", Ttl::from(r.ttl()).to_color())
                    }
                }
            }
            "rdata" => print!("{}", rr.r_data.to_color()),

            // OPT specific data
            "payload" => {
                if let Some(r) = rr.opt_or_class_ttl.opt() {
                    print!("{:<PAYLOAD_DISPLAY_LENGTH$}", r.payload())
                }
            }
            "extcode" => {
                if let Some(r) = rr.opt_or_class_ttl.opt() {
                    print!("{:<EXTCODE_DISPLAY_LENGTH$}", r.extended_rcode())
                }
            }
            "version" => {
                if let Some(r) = rr.opt_or_class_ttl.opt() {
                    print!("EDNS{:<VERSION_DISPLAY_LENGTH$}", r.version())
                }
            }
            "flags" => {
                if let Some(r) = rr.opt_or_class_ttl.opt() {
                    print!("{:<FLAGS_DISPLAY_LENGTH$}", r.flags())
                }
            }
            _ => (),
        }
    }
}

impl Show for ResourceRecord {
    fn show(&self, display_options: &DisplayOptions, length: Option<usize>) {
        let name_length = length.unwrap_or(NAME_DISPLAY_LENGTH);

        // formatting display
        if !display_options.fmt.is_empty() {
            display(
                self,
                &display_options.fmt,
                display_options.raw_ttl,
                name_length,
                display_options.puny,
            );
            println!();
            return;
        }

        // other options
        if display_options.short {
            println!("{}", self.r_data.to_color());
        } else if self.r#type != QType::OPT {
            const ALL_FIELDS: &str = "name,type,class,ttl,length,rdata";
            display(
                self,
                ALL_FIELDS,
                display_options.raw_ttl,
                name_length,
                display_options.puny,
            );
            println!();
        } else {
            const ALL_FIELDS: &str = "name,type,length,payload,extcode,version,flags,length,rdata";
            display(
                self,
                ALL_FIELDS,
                display_options.raw_ttl,
                name_length,
                display_options.puny,
            );
            println!();
        }
    }
}

pub trait ShowAll: Display {
    fn show_all(&self, display_options: &mut DisplayOptions, info: QueryInfo);
}

impl ShowAll for MessageList {
    fn show_all(&self, display_options: &mut DisplayOptions, info: QueryInfo) {
        //───────────────────────────────────────────────────────────────────────────────────
        // JSON
        //───────────────────────────────────────────────────────────────────────────────────
        if display_options.json_pretty {
            let j = serde_json::json!({
                "messages": self,
                "info": info
            });
            println!("{}", serde_json::to_string_pretty(&j).unwrap());
            return;
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // JSON pretty
        //───────────────────────────────────────────────────────────────────────────────────
        if display_options.json {
            let j = serde_json::json!({
                "messages": self,
                "info": info
            });
            println!("{}", serde_json::to_string(&j).unwrap());
            return;
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // fancy print out when only one message
        //───────────────────────────────────────────────────────────────────────────────────
        if self.len() == 1 {
            // we only have 1 message
            let msg = &self[0];
            let resp = msg.response();

            // when we only have one message, we print out a dig-like info
            display_options.sho_resp_header = true;
            display_options.show_headers = true;
            display_options.show_all = true;

            resp.show(display_options, None);

            // print out stats
            println!("{}", header_section("STATS", None));
            println!("{}", info);
        }
        //───────────────────────────────────────────────────────────────────────────────────
        // when several messages, just print out the ANSWER
        //───────────────────────────────────────────────────────────────────────────────────
        else {
            let max_length = self.max_length();

            for msg in self.iter() {
                msg.show(display_options, max_length);
            }

            if display_options.stats {
                println!("{}", info);
            }
        }
    }
}

pub trait ToColor: Display {
    fn to_color(&self) -> colored::ColoredString;
}

impl ToColor for RData {
    fn to_color(&self) -> colored::ColoredString {
        self.to_string().bright_yellow()
    }
}

impl ToColor for Ttl {
    fn to_color(&self) -> colored::ColoredString {
        self.to_string().bright_red()
    }
}

impl ToColor for QType {
    fn to_color(&self) -> colored::ColoredString {
        self.to_string().bright_blue()
    }
}

impl ToColor for DomainName {
    fn to_color(&self) -> colored::ColoredString {
        self.to_string().bright_green()
        // self.to_string().truecolor(NAME_COLOR.0, NAME_COLOR.1, NAME_COLOR.2)
    }
}

// pub const NAME_COLOR: (u8, u8, u8) = (100, 100, 100);
