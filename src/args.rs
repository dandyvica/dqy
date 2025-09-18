//! Manage command line arguments here.
use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use clap::builder::styling;
use clap::{crate_version, Arg, ArgAction, Command};
use http::*;
use log::{info, trace};
use rustc_version_runtime::version;
use simplelog::*;

use dnslib::dns::rfc::domain::DomainName;
use dnslib::dns::rfc::{flags::BitFlags, qclass::QClass, qtype::QType};
use dnslib::error::Error;
use dnslib::transport::network::{IPVersion, Protocol};
use dnslib::transport::{endpoint::EndPoint, TransportOptions};

use crate::cli_options::{DnsProtocolOptions, EdnsOptions};
use crate::config::{get_config, read_yaml};
use crate::show::{DisplayOptions, DumpOptions};

// value of the environment variable for flags if any
const ENV_FLAGS: &str = "DQY_FLAGS";

// help to set or unset flags
macro_rules! set_unset_flag {
    ($opt_flag:expr, $v:expr, $flag:literal, $bool:literal) => {
        // set or uset flag
        if $v.contains(&&$flag.to_string()) {
            $opt_flag = $bool;
        }
    };
}

//───────────────────────────────────────────────────────────────────────────────────
// This structure holds the command line arguments.
//───────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default, Clone)]
pub struct CliOptions {
    // DNS protocol options
    pub protocol: DnsProtocolOptions,

    // transport related
    pub transport: TransportOptions,

    // all flags
    pub flags: BitFlags,

    // EDNS options
    pub edns: EdnsOptions,

    // Display options
    pub display: DisplayOptions,

    // Dump options to save query or response
    pub dump: DumpOptions,
}

impl FromStr for CliOptions {
    type Err = dnslib::error::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let args: Vec<_> = s.split_ascii_whitespace().map(|a| a.to_string()).collect();
        CliOptions::options(&args, true)
    }
}

impl CliOptions {
    // Split vector of string according to the first dash found
    // Uses Cow to not recreate Vec<String> (might be overkill though 😀)
    fn split_args(args: &[String]) -> (Cow<'_, [String]>, Cow<'_, [String]>) {
        let pos = args.iter().position(|x| x.starts_with("-"));

        match pos {
            Some(pos) => (Cow::from(&args[0..pos]), Cow::from(&args[pos..])),
            None => (Cow::from(args), Cow::from(&[])),
        }
    }

    // helper func to allow unit tests with the DQY_FLAGS envvar which, if set, is set for all threads
    #[cfg(test)]
    fn get_test_args(args: &str) -> dnslib::error::Result<Self> {
        let args: Vec<_> = args.split_ascii_whitespace().map(|a| a.to_string()).collect();
        CliOptions::options(&args, false)
    }

    // the check_var is used to deal with unit tests which share the same process and so the same var
    pub fn options(args: &[String], check_var: bool) -> dnslib::error::Result<Self> {
        // save all cli options into a structure
        let mut options = CliOptions::default();

        // split args into 2 groups: with or without starting with a dash
        let (mut without_dash, mut with_dash) = Self::split_args(args);

        // check first if DQY_FLAGS is present
        if let Ok(env) = std::env::var(ENV_FLAGS) {
            if check_var {
                let env_args: Vec<String> = env.split_ascii_whitespace().map(|a| a.to_string()).collect();

                let (env_without_dash, env_with_dash) = Self::split_args(&env_args);
                without_dash.to_mut().extend(env_without_dash.into_owned());
                with_dash.to_mut().extend(env_with_dash.into_owned());
            }
        }

        /*         println!("options without dash:{:?}", without_dash);
        println!("options with dash:{:?}", with_dash); */

        let mut server = "";

        // build list of supported QTypes from txt file
        let supported_types = {
            let tmp: Vec<_> = include_str!("../doc/supported_types.txt")
                .split_ascii_whitespace()
                .collect();
            tmp.join(",")
        };

        //───────────────────────────────────────────────────────────────────────────────────
        // process the arguments not starting with a '-'
        //───────────────────────────────────────────────────────────────────────────────────
        for arg in without_dash.iter() {
            if let Some(s) = arg.strip_prefix('@') {
                server = s;
                continue;
            }

            // check if this is a domain (should include a dot)
            if arg.contains('.') {
                options.protocol.domain_string = arg.to_string();
                continue;
            }

            // otherwise it's a Qtype
            if let Ok(qt) = QType::from_str(arg.to_uppercase().as_str()) {
                options.protocol.qtype.push(qt);
                continue;
            }
        }

        let dqy_version = crate_version!();
        let about = format!(
            r#"
dqy v{}
A DNS query tool inspired by dig, drill and dog.
Compiled with rustc v{}

Project home page: https://github.com/dandyvica/dqy"#,
            dqy_version,
            version()
        );

        let usage = format!(
            r#"dqy [TYPES] [DOMAIN] [@RESOLVER] [OPTIONS]
            
Caveats: 

    - all options starting with a dash (-) should be placed after optional [TYPES] [DOMAIN] [@RESOLVER].
    - whenever you enter a singl-label domain name, it must ends with the root (.). E.g.: fr. or mx.

Supported query types: {}
            "#,
            supported_types
        );

        //───────────────────────────────────────────────────────────────────────────────────
        // now process the arguments starting with a '-'
        //───────────────────────────────────────────────────────────────────────────────────
        const STYLES: styling::Styles = styling::Styles::styled()
            .header(styling::AnsiColor::Green.on_default().bold())
            .usage(styling::AnsiColor::Green.on_default().bold())
            .literal(styling::AnsiColor::Blue.on_default().bold())
            .placeholder(styling::AnsiColor::Cyan.on_default());

        let mut cmd = Command::new("A DNS query tool inspired by dig, drill and dog")
            .version(crate_version!())
            .long_version(crate_version!())
            .styles(STYLES)
            .author("Alain Viguier dandyvica@gmail.com")
            .about(about)
            .after_long_help(include_str!("../doc/usage_examples.txt"))
            .bin_name("dqy")
            .no_binary_name(true)
            .override_usage(usage)
            .arg(
                Arg::new("type")
                    .short('t')
                    .long("type")
                    .long_help("Resource record type to query.")
                    .action(ArgAction::Set)
                    .num_args(1..255)
                    .value_delimiter(',')
                    .value_name("TYPE")
                    .value_parser(validate_qtypes)
                    //.default_value("NS")
            )
            .arg(
                Arg::new("class")
                    .short('c')
                    .long("class")
                    .long_help(
                        "Query class as specified in RFC1035. Possible values: IN, CS, CH, HS.",
                    )
                    .action(ArgAction::Set)
                    .value_name("CLASS")
                    .value_parser(clap::value_parser!(QClass))
                    .default_value("IN")
            )
            .arg(
                Arg::new("domain")
                    .short('d')
                    .long("domain")
                    .long_help("Domain name to query.")
                    .action(ArgAction::Set)
                    .required(false)
                    .value_name("DOMAIN")
            )
            .arg(
                Arg::new("ptr")
                    .short('x')
                    .long("ptr")
                    .long_help("Reverses DNS lookup. If used, other query types are ignored.")
                    .action(ArgAction::Set)
                    .value_name("PTR")
            )
            .arg(
                Arg::new("trace")
                    .long("trace")
                    .long_help("Iterative lookup from a random root server.")
                    .action(ArgAction::SetTrue)
            )
            //───────────────────────────────────────────────────────────────────────────────────
            // Protocol options
            //───────────────────────────────────────────────────────────────────────────────────  
            .arg(
                Arg::new("4")
                    .short('4')
                    .long("ipv4")
                    .long_help("Sets IP version 4. Only send queries to ipv4 enabled nameservers.")
                    .action(ArgAction::SetTrue)
                    .value_name("IPV4")
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("6")
                    .short('6')
                    .long("ipv6")
                    .long_help("Sets IP version 6. Only send queries to ipv6 enabled nameservers.")
                    .action(ArgAction::SetTrue)
                    .value_name("IPV6")
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("alpn")
                    .long("alpn")
                    .long_help("Forces ALPN protocol to 'DoT' for DNS over TLS queries.")
                    .action(ArgAction::SetTrue)
                    .value_name("ALPN")
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("cert")
                    .long("cert")
                    .long_help("Certificate PEM file when using DoT or DoH.")
                    .action(ArgAction::Set)
                    .value_name("CERT")
                    .value_parser(clap::value_parser!(PathBuf))
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("doq")
                    .long("doq")
                    .long_help("Sets transport to DNS over QUIC (DoQ).")
                    .visible_aliases(["DoQ", "quic"])
                    .action(ArgAction::SetTrue)
                    .value_name("doq")
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("https")
                    .short('H')
                    .long("https")
                    .long_help("Sets transport to DNS over https (DoH).")
                    .visible_aliases(["doh", "DoH"])
                    .action(ArgAction::SetTrue)
                    .value_name("https")
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("https-version")
                    .long("https-version")
                    .long_help("Sets the HTTPS version when using DNS over https (DoH).")
                    .action(ArgAction::Set)
                    .value_name("VERSION")
                    .value_parser(["v1", "v2", "v3"])
                    .default_value("v2")
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("no-recurse")
                    .long("no-recurse")
                    .long_help("Don't set the rd flag (recursion desired). Same as '--unset rd'.")
                    .action(ArgAction::SetTrue)
                    .value_name("no-recurse")
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("port")
                    .short('p')
                    .long("port")
                    .long_help("Optional DNS port number. If not specified, default port for the transport will be used (e.g.: 853 for DoT).")
                    .action(ArgAction::Set)
                    .value_name("PORT")
                    .value_parser(clap::value_parser!(u16))
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("resolv-file")
                    .short('r')
                    .long("resolv-file")
                    .long_help("Optional resolv.conf-like file from which the resolvers are taken.")
                    .action(ArgAction::Set)
                    .value_name("RESOLV.CONF")
                    .value_parser(clap::value_parser!(PathBuf))
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("sni")
                    .long("sni")
                    .long_help("Optional server name indication (SNI) for DoT.")
                    .action(ArgAction::Set)
                    .required(false)
                    .value_name("SNI")
                    .help_heading("Transport options")                    
            )
            .arg(
                Arg::new("tcp")
                    .short('T')
                    .long("tcp")
                    .long_help("Forces transport to TCP.")
                    .action(ArgAction::SetTrue)
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("timeout")
                    .long("timeout")
                    .long_help("Sets the timeout for network operations (in ms).")
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(u64))
                    .default_value("3000")
                    .value_name("TIMEOUT")
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("tls")
                    .short('S')
                    .long("tls")
                    .long_help("Forces transport to DNS over TLS (DoT).")
                    .visible_aliases(["dot", "DoT"])
                    .action(ArgAction::SetTrue)
                    .value_name("TLS")
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("set")
                    .long("set")
                    .long_help("Sets flags in the query header.")
                    .action(ArgAction::Set)
                    .num_args(1..=7)
                    .value_name("FLAGS")
                    .value_delimiter(',')
                    .value_parser(["aa", "ad", "cd", "ra", "rd", "tc", "z"])
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("unset")
                    .long("unset")
                    .long_help("Unsets flags in the query header. If a flag is set and unset, unset wins.")
                    .action(ArgAction::Set)
                    .num_args(1..=6)
                    .value_name("FLAGS")
                    .value_delimiter(',')
                    .value_parser(["aa", "ad", "cd", "ra", "rd", "tc", "z"])
                    .help_heading("Transport options")
            )
            //───────────────────────────────────────────────────────────────────────────────────
            // EDNS options
            //───────────────────────────────────────────────────────────────────────────────────   
            .arg(
                Arg::new("bufsize")
                    .long("bufsize")
                    .long_help("Sets the UDP message buffer size to BUFSIZE bytes in the OPT record.")
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(u16))
                    .default_value("1232")
                    .value_name("BUFSIZE")
                    .help_heading("EDNS options")
            )
            .arg(
                Arg::new("cookie")
                    .long("cookie")
                    .long_help("Sets EDNS COOKIE option in OPT record.")
                    .action(ArgAction::Set)
                    .value_name("COOKIE")
                    .num_args(0..=1)
                    .default_missing_value("")
                    .require_equals(true)
                    .help_heading("EDNS options")
            )
            // .arg(
            //     Arg::new("dau")
            //         .long("dau")
            //         .long_help("Sets the EDNS DAU option in the OPT record.")
            //         .value_delimiter(',')
            //         .action(ArgAction::Set)
            //         .value_parser(clap::value_parser!(u8))
            //         .num_args(1..=255)
            //         .value_name("ALG-CODE")
            //         .help_heading("EDNS options")
            // )
            // .arg(
            //     Arg::new("dhu")
            //         .long("dhu")
            //         .long_help("Sets the EDNS DHU option in the OPT record.")
            //         .value_delimiter(',')
            //         .action(ArgAction::Set)
            //         .value_parser(clap::value_parser!(u8))
            //         .num_args(1..=255)
            //         .value_name("ALG-CODE")
            //         .value_parser(clap::value_parser!(u8))
            //         .help_heading("EDNS options")
            // )
            .arg(
                Arg::new("dnssec")
                    .long("dnssec")
                    .long_help("Sets DNSSEC bit flag in OPT record.")
                    .action(ArgAction::SetTrue)
                    .value_name("DNSSEC FLAG")
                    .help_heading("EDNS options")
            )
            // .arg(
            //     Arg::new("n3u")
            //         .long("n3u")
            //         .long_help("Sets the EDNS N3U option in the OPT record.")
            //         .value_delimiter(',')
            //         .action(ArgAction::Set)
            //         .value_parser(clap::value_parser!(u8))
            //         .num_args(1..=255)
            //         .value_name("ALG-CODE")
            //         .value_parser(clap::value_parser!(u8))
            //         .help_heading("EDNS options")
            // )
            .arg(
                Arg::new("no-opt")
                    .long("no-opt")
                    .long_help("If set, no OPT record is sent.")
                    .action(ArgAction::SetTrue)
                    .help_heading("EDNS options")
            )
            .arg(
                Arg::new("nsid")
                    .long("nsid")
                    .long_help("Sets the EDNS NSID option in the OPT record.")
                    .action(ArgAction::SetTrue)
                    .help_heading("EDNS options")
            )
            .arg(
                Arg::new("padding")
                    .long("padding")
                    .long_help("Sets the EDNS Padding option in the OPT record to LENGTH.")
                    .action(ArgAction::Set)
                    .value_name("LENGTH")
                    .value_parser(clap::value_parser!(u16))
                    .help_heading("EDNS options")
            )
            .arg(
                Arg::new("zoneversion")
                    .long("zoneversion")
                    .long_help("Sets the EDNS ZONEVERSION option in the OPT record.")
                    .action(ArgAction::SetTrue)
                    .help_heading("EDNS options")
            )
            //───────────────────────────────────────────────────────────────────────────────────
            // Display options
            //───────────────────────────────────────────────────────────────────────────────────   
            .arg(
                Arg::new("align")
                    .long("align")
                    .long_help("Align domain names, useful for AXFR type.")
                    .action(ArgAction::SetTrue)
                    .value_name("ALIGN")
                    .help_heading("Display options")
            )
            .arg(
                Arg::new("fmt")
                    .long("fmt")
                    .long_help("User-defined format for RR output. Specify a list of comma-separated fields. Possible values: name, type, length, class, ttl, rdata. For OPT record: payload, extcode, version, flags. Ex: -fmt 'type,name,ttl,rdata'")
                    .action(ArgAction::Set)
                    .value_delimiter(',')
                    .value_parser(["name","type","length","class","ttl","rdata","payload","extcode","version","flags"])                    
                    .value_name("FORMAT")
                    .help_heading("Display options")
            )
            .arg(
                Arg::new("headers")
                    .long("headers")
                    .long_help("Show headers for each of the sections (answer, authorative, additional).")
                    .action(ArgAction::SetTrue)
                    .help_heading("Display options")
            )
            .arg(
                Arg::new("puny")
                    .long("puny")
                    .long_help("Print domain names as punycode instead of UTF-8.")
                    .action(ArgAction::SetTrue)
                    .help_heading("Display options")
            )
            .arg(
                Arg::new("json")
                    .short('j')
                    .long("json")
                    .long_help("Results are rendered as a JSON formatted string.")
                    .action(ArgAction::SetTrue)
                    .help_heading("Display options")
            )
            .arg(
                Arg::new("json-pretty")
                    .long("json-pretty")
                    .long_help("Records are rendered as a JSON pretty-formatted string.")
                    .action(ArgAction::SetTrue)
                    .help_heading("Display options")
            )
            // .arg(
            //     Arg::new("no-add")
            //         .long("no-add")
            //         .long_help("Don't show the additional RR section. Showed by default.")
            //         .action(ArgAction::SetTrue)
            //         .help_heading("Display options")
            // )
            // .arg(
            //     Arg::new("no-auth")
            //         .long("no-auth")
            //         .long_help("Don't show the authorative RR section. Showed by default.")
            //         .action(ArgAction::SetTrue)
            //         .help_heading("Display options")
            // )
            .arg(
                Arg::new("no-colors")
                    .long("no-colors")
                    .long_help("Don't color the output.")
                    .action(ArgAction::SetTrue)
                    .help_heading("Display options")
            )
            .arg(
                Arg::new("question")
                    .long("question")
                    .long_help("The question section is displayed.")
                    .action(ArgAction::SetTrue)
                    .help_heading("Display options")
            )
            .arg(
                Arg::new("raw-ttl")
                    .long("raw-ttl")
                    .long_help("Display TTL as seconds.")
                    .action(ArgAction::SetTrue)
                    .help_heading("Display options")
            )
            .arg(
                Arg::new("short")
                    .long("short")
                    .long_help("If set, only the RDATA part of a RR is showed.")
                    .action(ArgAction::SetTrue)
                    .help_heading("Display options")
            )
            .arg(
                Arg::new("show-all")
                    .long("show-all")
                    .long_help("If set, show all sections: answer, authorative, additional.")
                    .action(ArgAction::SetTrue)
                    .help_heading("Display options")
            )
            // .arg(
            //     Arg::new("show-opt")
            //         .long("show-opt")
            //         .long_help("If set, OPT record is displayed, if any.")
            //         .action(ArgAction::SetTrue)
            //         .help_heading("Display options")
            // )
            .arg(
                Arg::new("stats")
                    .long("stats")
                    .long_help("Prints out statistics about the query.")
                    .action(ArgAction::SetTrue)
                    .value_name("STATS")
                    .help_heading("Display options")
            )
            // .arg(
            //     Arg::new("tpl")
            //         .long("tpl")
            //         .hide(true)
            //         .long_help("Name of the handlebars template to render to display results.")
            //         .action(ArgAction::Set)
            //         .value_name("TEMPLATE")
            //         .value_parser(clap::value_parser!(PathBuf))
            //         .help_heading("Display options")
            // )
            .arg(
                Arg::new("verbose")
                    .short('v')
                    .long("verbose")
                    .long_help("Verbose mode, from info (-v) to trace (-vvvvv).")
                    .action(ArgAction::Count)
                    .help_heading("Display options")
            )
            //───────────────────────────────────────────────────────────────────────────────────
            // Misc. options
            //───────────────────────────────────────────────────────────────────────────────────   
            .arg(
                Arg::new("log")
                    .long("log")
                    .long_help("Save debugging info into the file LOG.")
                    .action(ArgAction::Set)
                    .value_name("LOG")
                    .value_parser(clap::value_parser!(PathBuf))
                    .help_heading("Miscellaneous options")
            )
            .arg(
                Arg::new("list-resolvers")
                    .long("list-resolvers")
                    .long_help("Do not query but list host resolvers (with port number) found and try to connect to them.")
                    .action(ArgAction::SetTrue)
                    .help_heading("Miscellaneous options")
            )
            .arg(
                Arg::new("write-response")
                    .long("wr")
                    .long_help("Write the response packet to FILE. Only valid for single-qtype queries.")
                    .action(ArgAction::Set)
                    .value_name("FILE")
                    .value_parser(clap::value_parser!(PathBuf))
                    .help_heading("Miscellaneous options")
            )
            .arg(
                Arg::new("write-query")
                    .long("wq")
                    .long_help("Write the query packet to FILE. Only valid for single-qtype queries.")
                    .action(ArgAction::Set)
                    .value_name("FILE")
                    .value_parser(clap::value_parser!(PathBuf))
                    .help_heading("Miscellaneous options")
            )
            ;

        // add Lua option if feature lua
        #[cfg(feature = "mlua")]
        {
            cmd = cmd.arg(
                Arg::new("lua")
                    .short('l')
                    .long("lua")
                    .long_help("Name of a lua script that will be called to display results.")
                    .action(ArgAction::Set)
                    .value_name("SCRIPT")
                    .value_parser(clap::value_parser!(PathBuf))
                    .help_heading("Miscellaneous options"),
            );
        }

        let matches = cmd.get_matches_from(with_dash.iter());

        //───────────────────────────────────────────────────────────────────────────────────
        // if no args without dash are provided, try to get the YAML config
        //───────────────────────────────────────────────────────────────────────────────────
        /*         if options.protocol.qtype.is_empty() {
            // get config file from current dir or home dir
            if let Some(cfg) = get_config() {
                let cfg_data = read_yaml(cfg)?;
                options.protocol.qtype = cfg_data.default_rrs;
            } else {
                options.protocol.qtype = vec![QType::NS];
            }
        } */

        //───────────────────────────────────────────────────────────────────────────────────
        // transport mode
        //───────────────────────────────────────────────────────────────────────────────────
        if matches.get_flag("tcp") {
            options.transport.transport_mode = Protocol::Tcp;
        }
        if matches.get_flag("tls") {
            options.transport.transport_mode = Protocol::DoT;
        }
        if matches.get_flag("https") || server.starts_with("https://") {
            options.transport.transport_mode = Protocol::DoH;

            // set HTTP version
            let v = matches.get_one::<String>("https-version").unwrap().to_string();

            match v.as_str() {
                "v1" => options.transport.https_version = Some(version::Version::HTTP_11),
                "v2" => options.transport.https_version = Some(version::Version::HTTP_2),
                "v3" => options.transport.https_version = Some(version::Version::HTTP_3),
                _ => unimplemented!("this version of HTTP is not implemented"),
            }
        }
        if matches.get_flag("doq") || server.starts_with("quic://") {
            options.transport.transport_mode = Protocol::DoQ;
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // port number is depending on transport mode or use one specified with --port
        //───────────────────────────────────────────────────────────────────────────────────
        options.transport.port = *matches
            .get_one::<u16>("port")
            .unwrap_or(&options.transport.transport_mode.default_port());

        //───────────────────────────────────────────────────────────────────────────────────
        // build the endpoint
        //───────────────────────────────────────────────────────────────────────────────────
        // resolver file is provided using --resolv-file
        if let Some(path) = matches.get_one::<PathBuf>("resolv-file") {
            // end point is build from these
            options.transport.endpoint = EndPoint::try_from((path, options.transport.port))?;
        }
        // no server provided: we use the host resolver
        else if server.is_empty() {
            options.transport.endpoint = EndPoint::try_from(options.transport.port)?;
        }
        // server was provided (e.g.: 1.1.1.1 or one.one.one.one)
        //
        // all possible cases:
        //
        // @1.1.1.1
        // @1.1.1.1:53
        // @2606:4700:4700::1111
        // @[2606:4700:4700::1111]:53
        // @one.one.one.one
        // @one.one.one.one:53
        // @https://cloudflare-dns.com/dns-query
        // @quic://dns.adguard.com
        else {
            options.transport.endpoint = EndPoint::new(server, options.transport.port)?;
        }

        trace!("ep={}", options.transport.endpoint);
        // std::process::exit(0);

        //───────────────────────────────────────────────────────────────────────────────────
        // QTypes
        //───────────────────────────────────────────────────────────────────────────────────
        if options.protocol.qtype.is_empty() {
            if let Some(v) = matches.get_many::<QType>("type") {
                let qtypes: Vec<_> = v.copied().collect();
                options.protocol.qtype = qtypes;
            } else {
                options.protocol.qtype = vec![QType::NS];
            }
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // QClass
        //───────────────────────────────────────────────────────────────────────────────────
        options.protocol.qclass = *matches.get_one::<QClass>("class").unwrap_or(&QClass::IN);

        //───────────────────────────────────────────────────────────────────────────────────
        // ip versions (Any is by default)
        //───────────────────────────────────────────────────────────────────────────────────
        if matches.get_flag("4") {
            options.transport.ip_version = IPVersion::V4;
        }
        if matches.get_flag("6") {
            options.transport.ip_version = IPVersion::V6;
        }

        // when providing an IPV6 address using @ (ex: @2001:678:8::3) and not providing the -6 flag
        // error occurs because by default, IPV4 is set. So in this case, reset to IPV6
        if options.transport.endpoint.is_ipv6() {
            options.transport.ip_version = IPVersion::V6;
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // recursion desired flag
        //───────────────────────────────────────────────────────────────────────────────────
        if matches.get_flag("no-recurse") {
            options.flags.recursion_desired = false;
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // if --domain, take it
        //───────────────────────────────────────────────────────────────────────────────────
        if let Some(domain) = matches.get_one::<String>("domain") {
            options.protocol.domain_string = domain.to_string();
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // bufsize
        //───────────────────────────────────────────────────────────────────────────────────
        options.transport.bufsize = *matches.get_one::<u16>("bufsize").unwrap();

        // only keep ipv4 or ipv6 addresses if -4 or -6 is provided
        options.transport.endpoint.retain(&options.transport.ip_version);

        //───────────────────────────────────────────────────────────────────────────────────
        // timeout
        //───────────────────────────────────────────────────────────────────────────────────
        options.transport.timeout = Duration::from_millis(*matches.get_one::<u64>("timeout").unwrap());

        //───────────────────────────────────────────────────────────────────────────────────
        // if reverse query, ignore all other options
        //───────────────────────────────────────────────────────────────────────────────────
        if let Some(ip) = matches.get_one::<String>("ptr") {
            // reverse query uses PTR
            options.protocol.qtype = vec![QType::PTR];
            options.protocol.qclass = QClass::IN;

            // try to convert to a valid IP address
            let addr = IpAddr::from_str(ip).map_err(|e| Error::IPParse(e, ip.to_string()))?;

            match addr {
                IpAddr::V4(_) => {
                    let mut limbs: Vec<_> = ip.split('.').collect();
                    limbs.reverse();
                    options.protocol.domain_string = format!("{}.in-addr.arpa", limbs.join("."));
                }
                IpAddr::V6(ipv6) => options.protocol.domain_string = ipv6_to_arpa(ipv6),
            }
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // Flags
        //───────────────────────────────────────────────────────────────────────────────────
        // all flags options are set to false except RD
        // set
        if let Some(v) = matches.get_many::<String>("set") {
            let flags: Vec<_> = v.collect();
            set_unset_flag!(options.flags.authorative_answer, flags, "aa", true);
            set_unset_flag!(options.flags.authentic_data, flags, "ad", true);
            set_unset_flag!(options.flags.checking_disabled, flags, "cd", true);
            set_unset_flag!(options.flags.recursion_available, flags, "ra", true);
            set_unset_flag!(options.flags.recursion_desired, flags, "rd", true);
            set_unset_flag!(options.flags.truncation, flags, "tc", true);
            set_unset_flag!(options.flags.z, flags, "z", true);
        }

        // unset
        if let Some(v) = matches.get_many::<String>("unset") {
            let flags: Vec<_> = v.collect();
            set_unset_flag!(options.flags.authorative_answer, flags, "aa", false);
            set_unset_flag!(options.flags.authentic_data, flags, "ad", false);
            set_unset_flag!(options.flags.checking_disabled, flags, "cd", false);
            set_unset_flag!(options.flags.recursion_available, flags, "ra", false);
            set_unset_flag!(options.flags.recursion_desired, flags, "rd", false);
            set_unset_flag!(options.flags.truncation, flags, "tc", false);
            set_unset_flag!(options.flags.z, flags, "z", false);
        }
        trace!("options flags: {:?}", options.flags);

        //───────────────────────────────────────────────────────────────────────────────────
        // EDNS or OPT record and options
        //───────────────────────────────────────────────────────────────────────────────────
        options.edns.no_opt = matches.get_flag("no-opt");
        options.edns.dnssec = matches.get_flag("dnssec");
        options.edns.nsid = matches.get_flag("nsid");
        options.edns.zoneversion = matches.get_flag("zoneversion");
        options.edns.padding = matches.get_one::<u16>("padding").copied();

        // options.edns.dau = matches.get_many::<u8>("dau").map(|v| v.copied().collect::<Vec<u8>>());
        // options.edns.dhu = matches.get_many::<u8>("dhu").map(|v| v.copied().collect::<Vec<u8>>());
        // options.edns.n3u = matches.get_many::<u8>("n3u").map(|v| v.copied().collect::<Vec<u8>>());

        // manage cookie option. Could be without cookie (no --cookie provided)
        // or --cookie alone (means random cookie), or --cookie=hexstring
        // --cookie or --cookie=hexstring was provided
        if matches.contains_id("cookie") {
            if let Some(cookie) = matches.get_one::<String>("cookie") {
                options.edns.cookie = Some(cookie.clone());
            }
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // manage display options
        //───────────────────────────────────────────────────────────────────────────────────
        options.display.align_names = matches.get_flag("align");
        options.display.show_headers = matches.get_flag("headers");
        options.display.json = matches.get_flag("json");
        options.display.json_pretty = matches.get_flag("json-pretty");
        // options.display.no_additional = matches.get_flag("no-add");
        // options.display.no_authorative = matches.get_flag("no-auth");
        options.display.show_question = matches.get_flag("question");
        options.display.raw_ttl = matches.get_flag("raw-ttl");
        options.display.short = matches.get_flag("short");
        options.display.show_all = matches.get_flag("show-all");
        //options.display.show_opt = matches.get_flag("show-opt");
        options.display.stats = matches.get_flag("stats");
        options.display.puny = matches.get_flag("puny");

        // handlebars template
        // if let Some(path) = matches.get_one::<PathBuf>("tpl") {
        //     // read handlebars file as a string
        //     options.display.hb_tpl =
        //         Some(std::fs::read_to_string(path).map_err(|e| Error::OpenFile(e, path.to_path_buf()))?);
        // }

        //───────────────────────────────────────────────────────────────────────────────────
        // manage misc. options
        //───────────────────────────────────────────────────────────────────────────────────
        if matches.contains_id("verbose") {
            let level = match matches.get_count("verbose") {
                0 => log::LevelFilter::Off,
                1 => log::LevelFilter::Info,
                2 => log::LevelFilter::Warn,
                3 => log::LevelFilter::Error,
                4 => log::LevelFilter::Debug,
                5..=255 => log::LevelFilter::Trace,
            };
            if let Some(path) = matches.get_one::<PathBuf>("log") {
                init_write_logger(path, level)?;
            } else {
                init_term_logger(level)?;
            }
        }

        // if QType is AXFR, auto-align
        if options.protocol.qtype == vec![QType::AXFR] {
            options.display.align_names = true;
        }

        // if no-colors, sets the NO_COLOR variable
        if matches.get_flag("no-colors") {
            std::env::set_var("NO_COLOR", "1");
        }

        // gather format string
        if let Some(v) = matches.get_many::<String>("fmt") {
            options.display.fmt = v.map(|f| f.to_string()).collect();
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // manage other misc. options
        //───────────────────────────────────────────────────────────────────────────────────
        options.display.trace = matches.get_flag("trace");

        //───────────────────────────────────────────────────────────────────────────────────
        // finally convert domain as a string to a domain name
        // internal domain name processing (IDNA)
        //───────────────────────────────────────────────────────────────────────────────────
        // if options.protocol.domain_string.len() != options.protocol.domain_string.chars().count() {
        //     let puny = idna::domain_to_ascii(&options.protocol.domain_string).map_err(Error::IDNA)?;
        //     options.protocol.domain_name = DomainName::try_from(puny.as_str())?;
        // } else {
        //     options.protocol.domain_name = DomainName::try_from(options.protocol.domain_string.as_str())?;
        // }
        options.protocol.domain_name = DomainName::try_from(options.protocol.domain_string.as_str())?;

        // for some types, use TCP instead of UDP right away
        if options.protocol.qtype.contains(&QType::ANY)
            || options.protocol.qtype.contains(&QType::AXFR) && options.transport.transport_mode == Protocol::Udp
        {
            options.transport.transport_mode = Protocol::Tcp;
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // open Lua script to load code
        //───────────────────────────────────────────────────────────────────────────────────
        #[cfg(feature = "mlua")]
        if let Some(path) = matches.get_one::<PathBuf>("lua") {
            // open Lua script and load code
            let code = std::fs::read_to_string(path).map_err(|e| Error::OpenFile(e, path.to_path_buf()))?;
            trace!("using Lua code from {}", path.display());
            options.display.lua_code = Some(code);
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // SNI & ALPN
        //───────────────────────────────────────────────────────────────────────────────────
        if let Some(d) = matches.get_one::<String>("sni") {
            options.transport.endpoint.sni = Some(d.to_string());
        }
        options.transport.alpn = matches.get_flag("alpn");

        //───────────────────────────────────────────────────────────────────────────────────
        // Cert file
        //───────────────────────────────────────────────────────────────────────────────────
        if let Some(path) = matches.get_one::<PathBuf>("cert") {
            // read PEM file
            let mut buf = Vec::new();
            let _ = File::open(path)
                .map_err(|e| Error::OpenFile(e, path.to_path_buf()))?
                .read_to_end(&mut buf)
                .map_err(|e| Error::OpenFile(e, path.to_path_buf()))?;

            options.transport.cert = Some(buf);
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // Dump options
        //───────────────────────────────────────────────────────────────────────────────────
        if let Some(path) = matches.get_one::<PathBuf>("write-query") {
            if options.protocol.qtype.len() == 1 {
                options.dump.write_query = Some(path.to_path_buf());
            }
        }

        if let Some(path) = matches.get_one::<PathBuf>("write-response") {
            if options.protocol.qtype.len() == 1 {
                options.dump.write_response = Some(path.to_path_buf());
            }
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // Dump resolvers
        //───────────────────────────────────────────────────────────────────────────────────
        if matches.get_flag("list-resolvers") {
            list_resolvers(&options.transport);
            std::process::exit(0);
        }

        Ok(options)
    }
}

// display list of found host resolvers and try to bind
fn list_resolvers(trp_options: &TransportOptions) {
    for addr in &trp_options.endpoint.addrs {
        // try to connect
        println!("addr: {} ", addr);
    }
}

// value QTypes on the command line when using the -type option
fn validate_qtypes(s: &str) -> std::result::Result<QType, String> {
    let qt_upper = s.to_uppercase();

    QType::from_str(&qt_upper).map_err(|e| format!("can't convert value '{e}' to a valid query type"))
}

// Initialize write logger: either create it or use it
fn init_write_logger(logfile: &PathBuf, level: log::LevelFilter) -> dnslib::error::Result<()> {
    if level == log::LevelFilter::Off {
        return Ok(());
    }

    // initialize logger
    let writable = OpenOptions::new()
        .create(true)
        .append(true)
        .open(logfile)
        .map_err(|e| Error::OpenFile(e, logfile.to_path_buf()))?;

    WriteLogger::init(
        level,
        simplelog::ConfigBuilder::new()
            .set_time_format_rfc3339()
            // .set_time_format_custom(format_description!(
            //     "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond]"
            .build(),
        writable,
    )
    .map_err(Error::Logger)?;

    Ok(())
}

// Initialize terminal logger
fn init_term_logger(level: log::LevelFilter) -> dnslib::error::Result<()> {
    if level == log::LevelFilter::Off {
        return Ok(());
    }
    TermLogger::init(level, Config::default(), TerminalMode::Stderr, ColorChoice::Auto).map_err(Error::Logger)?;

    Ok(())
}

// reverse ipv6 address to nibbles (for PTR)
fn ipv6_to_arpa(addr: Ipv6Addr) -> String {
    addr.segments() // get individual segments of the ipv6 address
        .iter()
        .map(|seg| format!("{:04x}", seg)) // pad with zeros
        .collect::<Vec<String>>() // expand to ["2001","0db8","0000","0000","0000","0000","0000","0001"]
        .join("") // join to get a string: "20010db8000000000000000000000001"
        .chars() // get individual chars
        .rev() // reverse the vector
        .map(|c| c.to_string()) // convert each char to a string
        .collect::<Vec<String>>() //create the vector
        .join(".")
        + ".ip6.arpa" // join each string (which is one char) with a dot
}

#[cfg(test)]
mod tests {

    use super::*;
    use dnslib::{dns::rfc::domain::ROOT};


    #[test]
    fn _split_args() {
        let args = "@1.1.1.1 A www.google.com --stats --https --dnssec";
        let v: Vec<_> = args.split(" ").map(|x| x.to_string()).collect();
        let (without, with) = CliOptions::split_args(&v);

        assert_eq!(without.join(" "), "@1.1.1.1 A www.google.com");
        assert_eq!(with.join(" "), "--stats --https --dnssec");

        let args = "@1.1.1.1 A www.google.com";
        let v: Vec<_> = args.split(" ").map(|x| x.to_string()).collect();
        let (without, with) = CliOptions::split_args(&v);

        assert_eq!(without.join(" "), "@1.1.1.1 A www.google.com");
        assert!(with.into_owned().is_empty());

        let args = "-stats --https --dnssec";
        let v: Vec<_> = args.split(" ").map(|x| x.to_string()).collect();
        let (without, with) = CliOptions::split_args(&v);

        assert_eq!(with.join(" "), "-stats --https --dnssec");
        assert!(without.into_owned().is_empty());
    }

    #[test]
    fn empty() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("")?;

        assert_eq!(opts.protocol.qtype, vec![QType::NS]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain_string, ROOT);
        assert_eq!(opts.transport.ip_version, IPVersion::Any);
        assert_eq!(opts.transport.transport_mode, Protocol::Udp);

        assert!(!opts.transport.alpn);
        assert!(opts.edns.cookie.is_none());
        assert!(opts.edns.padding.is_none());
        assert!(!opts.edns.dnssec);
        assert!(!opts.edns.no_opt);
        assert!(!opts.edns.nsid);
        assert!(!opts.edns.zoneversion);

        assert!(!opts.display.align_names);
        assert!(opts.display.fmt.is_empty());

        Ok(())
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // Main options
    //───────────────────────────────────────────────────────────────────────────────────
    #[test]
    fn qtype() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("A aaaa MX")?;
        assert_eq!(opts.protocol.qtype, vec![QType::A, QType::AAAA, QType::MX]);

        let opts = CliOptions::get_test_args("-t A,aaaa,MX")?;
        assert_eq!(opts.protocol.qtype, vec![QType::A, QType::AAAA, QType::MX]);

        let opts = CliOptions::get_test_args("--type A,aaaa,MX")?;
        assert_eq!(opts.protocol.qtype, vec![QType::A, QType::AAAA, QType::MX]);

        Ok(())
    }

    #[test]
    fn qclass() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("-c CH")?;
        assert_eq!(opts.protocol.qclass, QClass::CH);

        Ok(())
    }

    #[test]
    fn trace() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--trace")?;
        assert!(opts.display.trace);

        Ok(())
    }

    #[test]
    fn ptr() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--ptr 192.0.2.1")?;
        assert_eq!(opts.protocol.qtype, vec![QType::PTR]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(&opts.protocol.domain_string, "1.2.0.192.in-addr.arpa");

        let opts = CliOptions::get_test_args("-x 192.0.2.1")?;
        assert_eq!(&opts.protocol.domain_string, "1.2.0.192.in-addr.arpa");

        let opts = CliOptions::get_test_args("--ptr 2001:db8::567:89ab")?;
        assert_eq!(
            &opts.protocol.domain_string,
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );

        Ok(())
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // Transport options
    //───────────────────────────────────────────────────────────────────────────────────
    #[test]
    fn ipv4() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("-4")?;
        assert_eq!(opts.transport.ip_version, IPVersion::V4);

        let opts = CliOptions::get_test_args("--ipv4")?;
        assert_eq!(opts.transport.ip_version, IPVersion::V4);

        Ok(())
    }

    #[test]
    fn ipv6() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("-6")?;
        assert_eq!(opts.transport.ip_version, IPVersion::V6);

        let opts = CliOptions::get_test_args("--ipv6")?;
        assert_eq!(opts.transport.ip_version, IPVersion::V6);

        Ok(())
    }

    #[test]
    fn tcp() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("-T")?;
        assert_eq!(opts.transport.transport_mode, Protocol::Tcp);

        let opts = CliOptions::get_test_args("--tcp")?;
        assert_eq!(opts.transport.transport_mode, Protocol::Tcp);

        Ok(())
    }

    #[test]
    fn https() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("-H")?;
        assert_eq!(opts.transport.transport_mode, Protocol::DoH);
        assert_eq!(opts.transport.https_version, Some(version::Version::HTTP_2));

        let opts = CliOptions::get_test_args("--https")?;
        assert_eq!(opts.transport.transport_mode, Protocol::DoH);

        let opts = CliOptions::get_test_args("--doh")?;
        assert_eq!(opts.transport.transport_mode, Protocol::DoH);

        let opts = CliOptions::get_test_args("--DoH")?;
        assert_eq!(opts.transport.transport_mode, Protocol::DoH);

        Ok(())
    }

    #[test]
    fn https_version() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("-H --https-version v1")?;
        assert_eq!(opts.transport.https_version, Some(version::Version::HTTP_11));

        let opts = CliOptions::get_test_args("-H --https-version v2")?;
        assert_eq!(opts.transport.https_version, Some(version::Version::HTTP_2));

        let opts = CliOptions::get_test_args("-H --https-version v3")?;
        assert_eq!(opts.transport.https_version, Some(version::Version::HTTP_3));

        Ok(())
    }

    #[test]
    fn tls() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("-S")?;
        assert_eq!(opts.transport.transport_mode, Protocol::DoT);

        let opts = CliOptions::get_test_args("--tls")?;
        assert_eq!(opts.transport.transport_mode, Protocol::DoT);

        let opts = CliOptions::get_test_args("--dot")?;
        assert_eq!(opts.transport.transport_mode, Protocol::DoT);

        let opts = CliOptions::get_test_args("--DoT")?;
        assert_eq!(opts.transport.transport_mode, Protocol::DoT);

        Ok(())
    }

    #[test]
    fn quic() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--doq")?;
        assert_eq!(opts.transport.transport_mode, Protocol::DoQ);

        let opts = CliOptions::get_test_args("--DoQ")?;
        assert_eq!(opts.transport.transport_mode, Protocol::DoQ);

        let opts = CliOptions::get_test_args("--quic")?;
        assert_eq!(opts.transport.transport_mode, Protocol::DoQ);

        Ok(())
    }

    #[test]
    fn alpn() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--alpn")?;
        assert!(opts.transport.alpn);

        Ok(())
    }

    #[test]
    fn port() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("-p 1000")?;
        assert_eq!(opts.transport.port, 1000);

        let opts = CliOptions::get_test_args("--port=1000")?;
        assert_eq!(opts.transport.port, 1000);

        Ok(())
    }

    #[test]
    fn no_recurse() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--no-recurse")?;
        assert!(!opts.flags.recursion_desired);

        Ok(())
    }

    #[test]
    fn timeout() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--timeout=5000")?;
        assert_eq!(opts.transport.timeout, Duration::from_millis(5000));

        Ok(())
    }

    #[test]
    fn sni() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--sni www.foo.sni")?;
        assert_eq!(&opts.transport.endpoint.sni.unwrap(), "www.foo.sni");

        Ok(())
    }

    #[test]
    fn set_flags() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--set aa,ad,cd,ra,rd,tc,z")?;

        assert!(opts.flags.authorative_answer);
        assert!(opts.flags.authentic_data);
        assert!(opts.flags.checking_disabled);
        assert!(opts.flags.recursion_available);
        assert!(opts.flags.recursion_desired);
        assert!(opts.flags.truncation);
        assert!(opts.flags.z);

        Ok(())
    }

    #[test]
    fn unset_flags() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--unset aa,ad,cd,ra,rd,tc,z")?;

        assert!(!opts.flags.authorative_answer);
        assert!(!opts.flags.authentic_data);
        assert!(!opts.flags.checking_disabled);
        assert!(!opts.flags.recursion_available);
        assert!(!opts.flags.recursion_desired);
        assert!(!opts.flags.truncation);
        assert!(!opts.flags.z);

        Ok(())
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // EDNS options
    //───────────────────────────────────────────────────────────────────────────────────
    #[test]
    fn bufsize() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--bufsize 4096")?;

        assert_eq!(opts.transport.bufsize, 4096);

        Ok(())
    }

    #[test]
    fn cookie() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("")?;
        assert!(opts.edns.cookie.is_none());

        let opts = CliOptions::get_test_args("--cookie")?;
        assert!(opts.edns.cookie.is_some());

        let opts = CliOptions::get_test_args("--cookie=ABCDEF")?;
        assert_eq!(opts.edns.cookie.unwrap(), "ABCDEF");

        Ok(())
    }

    #[test]
    fn dnssec() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--dnssec")?;

        assert!(opts.edns.dnssec);

        Ok(())
    }

    #[test]
    fn no_opt() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--no-opt")?;

        assert!(opts.edns.no_opt);

        Ok(())
    }

    #[test]
    fn nsid() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--nsid")?;

        assert!(opts.edns.nsid);

        Ok(())
    }

    #[test]
    fn padding() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--padding 20")?;

        assert_eq!(opts.edns.padding, Some(20));

        Ok(())
    }

    #[test]
    fn zoneversion() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--zoneversion")?;

        assert!(opts.edns.zoneversion);

        Ok(())
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // Display options
    //───────────────────────────────────────────────────────────────────────────────────
    #[test]
    fn align() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--align")?;

        assert!(opts.display.align_names);

        Ok(())
    }

    #[test]
    fn format() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--fmt name,type,length,class,ttl,rdata,payload,extcode,version")?;

        assert_eq!(
            opts.display.fmt,
            vec!["name", "type", "length", "class", "ttl", "rdata", "payload", "extcode", "version"]
        );

        Ok(())
    }

    #[test]
    fn header() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--headers")?;

        assert!(opts.display.show_headers);

        Ok(())
    }

    #[test]
    fn puny() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--puny")?;

        assert!(opts.display.puny);

        Ok(())
    }

    #[test]
    fn json() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--json")?;
        assert!(opts.display.json);

        let opts = CliOptions::get_test_args("-j")?;
        assert!(opts.display.json);

        let opts = CliOptions::get_test_args("--json-pretty")?;
        assert!(opts.display.json_pretty);

        Ok(())
    }

    #[test]
    fn no_colors() -> dnslib::error::Result<()> {
        let _ = CliOptions::get_test_args("--no-colors")?;

        match std::env::var("NO_COLOR") {
            Ok(val) => assert_eq!(&val, "1"),
            Err(_) => assert!(false),
        }

        Ok(())
    }

    #[test]
    fn question() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--question")?;

        assert!(opts.display.show_question);

        Ok(())
    }

    #[test]
    fn raw_ttl() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--raw-ttl")?;

        assert!(opts.display.raw_ttl);

        Ok(())
    }

    #[test]
    fn short() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--short")?;

        assert!(opts.display.short);

        Ok(())
    }

    #[test]
    fn stats() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("--stats")?;

        assert!(opts.display.stats);

        Ok(())
    }

    #[test]
    fn with_class() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("-t AAAA -c CH -d www.google.com")?;

        assert_eq!(opts.protocol.qtype, vec![QType::AAAA]);
        assert_eq!(opts.protocol.qclass, QClass::CH);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain_string, "www.google.com");
        assert_eq!(opts.transport.ip_version, IPVersion::Any);
        assert_eq!(opts.transport.transport_mode, Protocol::Udp);

        Ok(())
    }

    #[test]
    fn with_no_dash() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("@1.1.1.1 A AAAA MX www.google.com")?;

        assert_eq!(opts.protocol.qtype, vec![QType::A, QType::AAAA, QType::MX]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain_string, "www.google.com");
        assert_eq!(opts.transport.ip_version, IPVersion::Any);
        assert_eq!(opts.transport.transport_mode, Protocol::Udp);
        assert_eq!(&opts.transport.endpoint.server_name, "1.1.1.1");

        Ok(())
    }

    #[test]
    fn with_ipv6() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("@2606:4700:4700::1111 A AAAA MX www.google.com -6")?;

        assert_eq!(opts.protocol.qtype, vec![QType::A, QType::AAAA, QType::MX]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain_string, "www.google.com");
        assert_eq!(opts.transport.ip_version, IPVersion::V6);
        assert_eq!(opts.transport.transport_mode, Protocol::Udp);
        assert_eq!(&opts.transport.endpoint.server_name, "2606:4700:4700::1111");

        Ok(())
    }

    #[test]
    fn with_tcp() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("@2606:4700:4700::1111 A AAAA MX www.google.com --tcp -6")?;

        assert_eq!(opts.protocol.qtype, vec![QType::A, QType::AAAA, QType::MX]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain_string, "www.google.com");
        assert_eq!(opts.transport.ip_version, IPVersion::V6);
        assert_eq!(opts.transport.transport_mode, Protocol::Tcp);

        Ok(())
    }

    #[test]
    fn with_ptr() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("@1.1.1.1 A AAAA MX www.google.com -4 --tcp -x 1.2.3.4")?;

        assert_eq!(opts.protocol.qtype, vec![QType::PTR]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain_string, "4.3.2.1.in-addr.arpa");
        assert_eq!(opts.transport.ip_version, IPVersion::V4);
        assert_eq!(opts.transport.transport_mode, Protocol::Tcp);

        Ok(())
    }

    #[test]
    fn with_dnssec() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("@1.1.1.1 A www.google.com --dnssec --set cd --unset aa")?;

        assert!(opts.edns.dnssec);
        assert!(opts.flags.checking_disabled);
        assert!(!opts.flags.authorative_answer);

        Ok(())
    }

    #[test]
    fn with_env() -> dnslib::error::Result<()> {
        std::env::set_var("DQY_FLAGS", "@1.1.1.1 --dnssec");

        // in this case, due to envvar collision, we don't use from_str and set check_var to false
        // to not check DQY_FLAGS
        let args: Vec<_> = "www.google.com --set cd --unset aa"
            .split_ascii_whitespace()
            .map(|a| a.to_string())
            .collect();
        let opts = CliOptions::options(&args, true)?;

        assert_eq!(&opts.transport.endpoint.server_name, "1.1.1.1");
        assert!(opts.edns.dnssec);
        assert!(opts.flags.checking_disabled);
        assert!(!opts.flags.authorative_answer);

        std::env::remove_var("DQY_FLAGS");        

        Ok(())
    }

    #[test]
    #[cfg(feature = "mlua")]
    fn lua() -> dnslib::error::Result<()> {
        let opts = CliOptions::get_test_args("@1.1.1.1 A www.google.com --lua tests/sample.lua")?;

        Ok(())        
    }
}
