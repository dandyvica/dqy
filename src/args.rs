//! Manage command line arguments here.
use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use clap::{Arg, ArgAction, Command};
use http::*;
use log::{debug, info, trace};
use rustc_version_runtime::version;
use simplelog::*;

use crate::cli_options::{DnsProtocolOptions, EdnsOptions};
use crate::dns::rfc::domain::DomainName;
use crate::dns::rfc::{flags::BitFlags, qclass::QClass, qtype::QType};
use crate::error::Error;
use crate::show::{DisplayOptions, DumpOptions};
use crate::transport::network::{IPVersion, Protocol};
use crate::transport::{endpoint::EndPoint, TransportOptions};

// value of the environment variable for flags if any
const ENV_FLAGS: &str = "DQY_FLAGS";
const VERSION: &str = "0.3.0";

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
    type Err = crate::error::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let args: Vec<_> = s.split_ascii_whitespace().map(|a| a.to_string()).collect();
        CliOptions::options(&args)
    }
}

impl CliOptions {
    // process target resolver passed in arg after @ char
    // different possibilities for naming:
    //
    // @1.1.1.1
    // @1.1.1.1:53
    // 2606:4700:4700::1111
    // @a.root-servers.net.
    // @[2606:4700:4700::1111]:53
    // @https://cloudflare-dns.com/dns-query
    // @https://104.16.249.249/dns-query
    // @https://2606:4700::6810:f9f9/dns-query
    // @one.one.one.one
    // @one.one.one.one:53
    // fn analyze_resolver(server: &str, trp_options: &mut TransportOptions) -> crate::error::Result<EndPoint> {
    //     // if https:// is found in the server, it's DoH
    //     if server.starts_with("https://") {
    //         trp_options.transport_mode = Protocol::DoH;
    //         //trp_options.doh = true;
    //         EndPoint::try_from(server)
    //     }
    //     // if quic:// is found in the server, it's DoQ
    //     else if server.starts_with("quic://") {
    //         trp_options.transport_mode = Protocol::DoQ;
    //         // trp_options.doq = true;
    //         EndPoint::try_from(server)
    //     }
    //     // this is a pattern like: @[2606:4700:4700::1111]:53
    //     else {
    //         let re = Regex::new(r"\]:\d+$").unwrap();
    //         if re.is_match(server) {
    //             EndPoint::try_from(server)
    //         } else {
    //             EndPoint::try_from((server, trp_options.port))
    //         }
    //     }
    // }

    // Split vector of string according to the first dash found
    // Uses Cow to not recreate Vec<String> (might be overkill though 😀)
    fn split_args(args: &[String]) -> (Cow<'_, [String]>, Cow<'_, [String]>) {
        let pos = args.iter().position(|x| x.starts_with("-"));

        match pos {
            Some(pos) => (Cow::from(&args[0..pos]), Cow::from(&args[pos..])),
            None => (Cow::from(args), Cow::from(&[])),
        }
    }

    pub fn options(args: &[String]) -> crate::error::Result<Self> {
        // save all cli options into a structure
        let mut options = CliOptions::default();

        // split args into 2 groups: with or without starting with a dash
        let (mut without_dash, mut with_dash) = Self::split_args(args);

        // check first if DQY_FLAGS is present
        if let Ok(env) = std::env::var(ENV_FLAGS) {
            let env_args: Vec<String> = env.split_ascii_whitespace().map(|a| a.to_string()).collect();

            let (env_without_dash, env_with_dash) = Self::split_args(&env_args);
            without_dash.to_mut().extend(env_without_dash.into_owned());
            with_dash.to_mut().extend(env_with_dash.into_owned());
        }

        // println!("options without dash:{:?}", without_dash);
        // println!("options with dash:{:?}", with_dash);

        let mut server = "";

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
                options.protocol.domain = arg.to_string();
                continue;
            }

            // otherwise it's a Qtype
            if let Ok(qt) = QType::from_str(arg.to_uppercase().as_str()) {
                options.protocol.qtype.push(qt);
                continue;
            }
        }

        let rustc_version = format!("compiled with rustc v{}", version());
        let about = format!(
            r#"
A DNS query tool inspired by dig, drill and dog.
Compiled with rustc v{}

Project home page: https://github.com/dandyvica/dqy
                
"#,
            version()
        );

        //───────────────────────────────────────────────────────────────────────────────────
        // now process the arguments starting with a '-'
        //───────────────────────────────────────────────────────────────────────────────────
        let cmd = Command::new("A DNS query tool inspired by dig, drill and dog")
            .version(VERSION)
            .author("Alain Viguier dandyvica@gmail.com")
            .about(about)
            .after_help(rustc_version)
            .after_long_help(include_str!("../doc/usage_examples.txt"))
            .bin_name("dqy")
            .no_binary_name(true)
            .override_usage(r#"dqy [TYPES] [DOMAIN] [@RESOLVER] [OPTIONS]
            
Caveat: all options starting with a dash (-) should be placed after optional [TYPES] [DOMAIN] [@RESOLVER].
            "#)
            .arg(
                Arg::new("type")
                    .short('t')
                    .long("type")
                    .long_help("Resource record type to query.")
                    .action(ArgAction::Append)
                    .num_args(1..255)
                    .value_delimiter(',')
                    .value_name("TYPE")
                    .value_parser(validate_qtypes)
                    .default_value("NS")
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
                    .long("ip4")
                    .long_help("Sets IP version 4. Only send queries to ipv4 enabled nameservers.")
                    .action(ArgAction::SetTrue)
                    .value_name("IPV4")
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("6")
                    .short('6')
                    .long("ip6")
                    .long_help("Sets IP version 6. Only send queries to ipv6 enabled nameservers.")
                    .action(ArgAction::SetTrue)
                    .value_name("IPV6")
                    .help_heading("Transport options")
            )
            .arg(
                Arg::new("alpn")
                    .long("alpn")
                    .long_help("Forces ALPN protocol to DoT.")
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
                    .value_name("https-version")
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
                Arg::new("resolve-file")
                    .short('r')
                    .long("resolve-file")
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
                    .num_args(1..=6)
                    .value_name("FLAGS")
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
                    .long_help("Sets the EDNS NSID option in the OPT record.")
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
                Arg::new("idna")
                    .long("idna")
                    .long_help("Convert back IDNA domain names to UTF-8 during display.")
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
            .arg(
                Arg::new("no-add")
                    .long("no-add")
                    .long_help("Don't show the additional RR section. Showed by default.")
                    .action(ArgAction::SetTrue)
                    .help_heading("Display options")
            )
            .arg(
                Arg::new("no-auth")
                    .long("no-auth")
                    .long_help("Don't show the authorative RR section. Showed by default.")
                    .action(ArgAction::SetTrue)
                    .help_heading("Display options")
            )
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
                Arg::new("show-opt")
                    .long("show-opt")
                    .long_help("If set, OPT record is displayed, if any.")
                    .action(ArgAction::SetTrue)
                    .help_heading("Display options")
            )
            .arg(
                Arg::new("stats")
                    .long("stats")
                    .long_help("Prints out statistics around the query.")
                    .action(ArgAction::SetTrue)
                    .value_name("STATS")
                    .help_heading("Display options")
            )
            // .arg(
            //     Arg::new("tpl")
            //         .long("tpl")
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
                Arg::new("read-query")
                    .long("rq")
                    .long_help("Read query from file.")
                    .action(ArgAction::Set)
                    .value_name("FILE")
                    .value_parser(clap::value_parser!(PathBuf))
                    .help_heading("Miscellaneous options")
            )
            .arg(
                Arg::new("write-query")
                    .long("wq")
                    .long_help("Write an answer packet to file. If several types are requested, the last answer packet if saved")
                    .action(ArgAction::Set)
                    .value_name("FILE")
                    .value_parser(clap::value_parser!(PathBuf))
                    .help_heading("Miscellaneous options")
            )
            ;

        // add Lua option if feature lua
        #[cfg(feature = "mlua")]
        let cmd = cmd.arg(
            Arg::new("lua")
                .short('l')
                .long("lua")
                .long_help("Name of a lua script that will be called to display results.")
                .action(ArgAction::Set)
                .value_name("lua")
                .value_parser(clap::value_parser!(PathBuf))
                .help_heading("Display options"),
        );

        let matches = cmd.get_matches_from(with_dash.iter());

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
        // resolver file is provided using --resolve-file
        if let Some(path) = matches.get_one::<PathBuf>("resolve-file") {
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
        // QTypes, QClass
        //───────────────────────────────────────────────────────────────────────────────────
        if options.protocol.qtype.is_empty() {
            let vals: Vec<QType> = matches.get_many("type").unwrap().copied().collect();
            options.protocol.qtype = vals;
        }
        options.protocol.qclass = *matches.get_one::<QClass>("class").unwrap();

        //───────────────────────────────────────────────────────────────────────────────────
        // ip versions (Any is by default)
        //───────────────────────────────────────────────────────────────────────────────────
        if matches.get_flag("4") {
            options.transport.ip_version = IPVersion::V4;
        }
        if matches.get_flag("6") {
            options.transport.ip_version = IPVersion::V6;
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // recursion desired flag
        //───────────────────────────────────────────────────────────────────────────────────
        if matches.get_flag("no-recurse") {
            options.flags.recursion_desired = false;
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // if no domain to query, by default set root (.)
        //───────────────────────────────────────────────────────────────────────────────────
        if let Some(d) = matches.get_one::<String>("domain") {
            options.protocol.domain = d.to_string();
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
        // internal domain name processing (IDNA)
        //───────────────────────────────────────────────────────────────────────────────────
        if options.protocol.domain.len() != options.protocol.domain.chars().count() {
            options.protocol.domain = idna::domain_to_ascii(&options.protocol.domain).unwrap();
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // if reverse query, ignore all other options
        //───────────────────────────────────────────────────────────────────────────────────
        if let Some(ip) = matches.get_one::<String>("ptr") {
            // reverse query uses PTR
            options.protocol.qtype = vec![QType::PTR];
            options.protocol.qclass = QClass::IN;

            // try to convert to a valid IP address
            let addr = IpAddr::from_str(ip).map_err(|e| Error::IPParse(e, ip.to_string()))?;

            if addr.is_ipv4() {
                let mut limbs: Vec<_> = ip.split('.').collect();
                limbs.reverse();
                options.protocol.domain = format!("{}.in-addr.arpa", limbs.join("."));
            } else {
                // get individual u8 values because an ipv6 address might omit a heading 0
                // ex: 2001:470:30:84:e276:63ff:fe72:3900 => 2001:0470:0030:84:e276:63ff:fe72:3900

                // this will convert to ["2001", "0470", "0030", "0084", "e276", "63ff", "fe72", "3900"]
                let split = ip
                    .split(':') // split accordsing to ":"
                    .map(|x| format!("{:0>4}", x)) // convert to string with heading 0
                    .collect::<Vec<String>>()
                    .join(""); // and finally join to get a whole string

                // now reverse and join each digit with .
                let mut domain: Vec<_> = split.split("").filter(|x| !x.is_empty()).collect();
                domain.reverse();

                options.protocol.domain = format!("{}.ip6.arpa", domain.join("."));
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
        options.display.headers = matches.get_flag("headers");
        options.display.json = matches.get_flag("json");
        options.display.json_pretty = matches.get_flag("json-pretty");
        options.display.no_additional = matches.get_flag("no-add");
        options.display.no_authorative = matches.get_flag("no-auth");
        options.display.question = matches.get_flag("question");
        options.display.raw_ttl = matches.get_flag("raw-ttl");
        options.display.short = matches.get_flag("short");
        options.display.show_opt = matches.get_flag("show-opt");
        options.display.stats = matches.get_flag("stats");
        options.display.idna = matches.get_flag("idna");

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

        if let Some(fmt) = matches.get_one::<String>("fmt") {
            options.display.fmt = fmt.to_string();
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // manage other misc. options
        //───────────────────────────────────────────────────────────────────────────────────
        options.display.trace = matches.get_flag("trace");

        // finally convert domain as a string to a domain name
        options.protocol.domain_name = DomainName::try_from(options.protocol.domain.as_str())?;

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
            let code = std::fs::read_to_string(path)?;
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
            options.dump.write_query = Some(path.to_path_buf());
        }

        Ok(options)
    }
}

// value QTypes on the command line when using the -type option
fn validate_qtypes(s: &str) -> std::result::Result<QType, String> {
    let qt_upper = s.to_uppercase();

    QType::from_str(&qt_upper).map_err(|e| format!("can't convert value '{e}' to a valid query type"))
}

// Initialize write logger: either create it or use it
fn init_write_logger(logfile: &PathBuf, level: log::LevelFilter) -> crate::error::Result<()> {
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
fn init_term_logger(level: log::LevelFilter) -> crate::error::Result<()> {
    if level == log::LevelFilter::Off {
        return Ok(());
    }
    TermLogger::init(level, Config::default(), TerminalMode::Stderr, ColorChoice::Auto).map_err(Error::Logger)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env::set_var;

    use crate::dns::rfc::domain::ROOT;

    use super::*;

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
    fn empty() {
        let opts = CliOptions::from_str("");
        println!("opts={:?}", opts);
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.protocol.qtype, vec![QType::NS]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain, ROOT);
        assert_eq!(opts.transport.ip_version, IPVersion::Any);
        assert_eq!(opts.transport.transport_mode, Protocol::Udp);
    }

    #[test]
    fn with_domain1() {
        let opts = CliOptions::from_str("-d www.google.com");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.protocol.qtype, vec![QType::NS]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain, "www.google.com");
        assert_eq!(opts.transport.ip_version, IPVersion::Any);
        assert_eq!(opts.transport.transport_mode, Protocol::Udp);
    }

    #[test]
    fn with_domain2() {
        let opts = CliOptions::from_str("-t AAAA -c CH -d www.google.com");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.protocol.qtype, vec![QType::AAAA]);
        assert_eq!(opts.protocol.qclass, QClass::CH);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain, "www.google.com");
        assert_eq!(opts.transport.ip_version, IPVersion::Any);
        assert_eq!(opts.transport.transport_mode, Protocol::Udp);
    }

    #[test]
    fn with_no_dash() {
        let opts = CliOptions::from_str("@1.1.1.1 A AAAA MX www.google.com");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.protocol.qtype, vec![QType::A, QType::AAAA, QType::MX]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain, "www.google.com");
        assert_eq!(opts.transport.ip_version, IPVersion::Any);
        assert_eq!(opts.transport.transport_mode, Protocol::Udp);
        assert_eq!(&opts.transport.endpoint.server_name, "1.1.1.1");
    }

    #[test]
    fn with_ipv6() {
        let opts = CliOptions::from_str("@2606:4700:4700::1111 A AAAA MX www.google.com -6");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.protocol.qtype, vec![QType::A, QType::AAAA, QType::MX]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain, "www.google.com");
        assert_eq!(opts.transport.ip_version, IPVersion::V6);
        assert_eq!(opts.transport.transport_mode, Protocol::Udp);
        assert_eq!(&opts.transport.endpoint.server_name, &"2606:4700:4700::1111");
    }

    #[test]
    fn with_tcp() {
        let opts = CliOptions::from_str("@2606:4700:4700::1111 A AAAA MX www.google.com --tcp -6");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.protocol.qtype, vec![QType::A, QType::AAAA, QType::MX]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain, "www.google.com");
        assert_eq!(opts.transport.ip_version, IPVersion::V6);
        assert_eq!(opts.transport.transport_mode, Protocol::Tcp);
    }

    #[test]
    fn with_ptr() {
        let opts = CliOptions::from_str("@1.1.1.1 A AAAA MX www.google.com -4 --tcp -x 1.2.3.4");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.protocol.qtype, vec![QType::PTR]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain, "4.3.2.1.in-addr.arpa");
        assert_eq!(opts.transport.ip_version, IPVersion::V4);
        assert_eq!(opts.transport.transport_mode, Protocol::Tcp);
    }

    #[test]
    fn plus() {
        let opts = CliOptions::from_str("@1.1.1.1 A www.google.com --dnssec --set cd --unset aa");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert!(opts.edns.dnssec);
        assert!(opts.flags.checking_disabled);
        assert!(!opts.flags.authorative_answer);
    }

    //#[test]
    fn with_env() {
        std::env::set_var("DQY_FLAGS", "@1.1.1.1 --dnssec");

        let opts = CliOptions::from_str("www.google.com --set cd --unset aa");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(&opts.transport.endpoint.server_name, "1.1.1.1");

        std::env::set_var("DQY_FLAGS", "");

        // assert!(opts.edns.dnssec);
        // assert!(opts.flags.checking_disabled);
        // assert!(!opts.flags.authorative_answer);
    }
}
