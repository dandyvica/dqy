//! Manage command line arguments here.
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;

//use crate::plus;

use crate::plus::PlusArgList;

use super::plus::PlusArg;

use clap::{Arg, ArgAction, Command};

//use log::debug;

use dns::err_internal;
use dns::{
    error::{DNSResult, Error, ProtocolError},
    rfc::{qclass::QClass, qtype::QType},
    transport::mode::{IPVersion, TransportMode},
};

use log::trace;
use resolver::ResolverList;

macro_rules! plus_arg_bool {
    ($opt:expr, $field:ident, $map:ident) => {
        // option is found is the list of + arguments
        if $map.contains(stringify!($field)) {
            let pa = &$map[stringify!($field)];
            $opt.$field = !pa.is_no();
        }
    };
}

//────────────────────────────────────────────────────────────────────────────────────────────
// List of flags to set or not
//
// Useful: https://serverfault.com/questions/729025/what-are-all-the-flags-in-a-dig-response
//────────────────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default)]
pub struct QueryFlags {
    // AA = Authoritative Answer
    pub aaflag: bool,

    // AD = Authenticated Data (for DNSSEC only; indicates that the data was authenticated)
    pub adflag: bool,

    // CD = Checking Disabled (DNSSEC only; disables checking at the receiving server)
    pub cdflag: bool,

    // RA = Recursion Available (if set, denotes recursive query support is available)
    pub raflag: bool,

    // RD = Recursion Desired (set in a query and copied into the response if recursion is supported)
    pub rdflag: bool,

    // TC TrunCation (truncated due to length greater than that permitted on the transmission channel)
    pub tcflag: bool,
}

#[derive(Debug, Default)]
//───────────────────────────────────────────────────────────────────────────────────
// EDNS options
//───────────────────────────────────────────────────────────────────────────────────
pub struct Edns {
    // This option requests that DNSSEC records be sent by setting the DNSSEC OK (DO) bit in the OPT record in the
    // additional section of the query.
    pub dnssec: bool,

    // add NSID option if true
    pub nsid: bool,

    // padding if the form of +padding=20
    pub padding: Option<u16>,

    // DAU, DHU, N3U same process
    pub dau: Option<Vec<u8>>,
    pub dhu: Option<Vec<u8>>,
    pub n3u: Option<Vec<u8>>,

    // edns-key-tag
    pub keytag: Option<Vec<u16>>,
}

#[derive(Debug, Default)]
//───────────────────────────────────────────────────────────────────────────────────
// Transport options
//───────────────────────────────────────────────────────────────────────────────────
pub struct Transport {
    // UPD, TCP, DoH or DoT
    pub transport_mode: TransportMode,

    // V4 or V6
    pub ip_version: IPVersion,

    // timeout for network operations
    pub timeout: Duration,

    // resolver
    pub resolver: String,

    // if true, elasped time and some stats are printed out
    pub stats: bool,

    // buffer size of EDNS0
    pub bufsize: u16,

    // true if TLS/DoT
    pub tls: bool,
    pub dot: bool,

    // true if TCP
    pub tcp: bool,

    // true if HTTPS/DOH
    pub https: bool,
    pub doh: bool,

    // ip port destination (53 for udp/tcp, 853 for DoT, 443 for DoH)
    pub port: u16,
}

#[derive(Debug, Default)]
//───────────────────────────────────────────────────────────────────────────────────
// Protocol options: linked to the DNS protocol itself
//───────────────────────────────────────────────────────────────────────────────────
pub struct Protocol {
    pub qtype: Vec<QType>,

    // Qclass is IN by default
    pub qclass: QClass,

    // list of resolvers found in the client machine
    pub resolvers: Vec<SocketAddr>,

    // domain name to query. IDNA domains are punycoded before being sent
    pub domain: String,

    // server is the name passed after @
    pub server: String,
}

#[derive(Debug, Default)]
//───────────────────────────────────────────────────────────────────────────────────
// Display options
//───────────────────────────────────────────────────────────────────────────────────
pub struct Display {
    // print out stats like elasped time etc
    pub stats: bool,
}

/// This structure holds the command line arguments.
#[derive(Debug, Default)]
pub struct CliOptions {
    // DNS protocol options
    pub protocol: Protocol,

    // transport related
    pub transport: Transport,

    // all flags
    pub flags: QueryFlags,

    // EDNS options
    pub edns: Edns,

    // Display options
    pub display: Display,
}

impl CliOptions {
    pub fn options(args: &[String]) -> DNSResult<Self> {
        // save all cli options into a structure
        let mut options = CliOptions::default();

        // split arguments into 2 sets: those not starting with a '-' which should be first
        // and the others
        let dash_pos = args.iter().position(|arg| arg.starts_with('-'));
        //println!("dash_pos={:?}", dash_pos);

        let (without_dash, with_dash) = match dash_pos {
            Some(pos) => (&args[0..pos], &args[pos..]),
            None => (&args[..], &[] as &[String]),
        };

        // hold the + arguments like +short, +bufsize=4096 or +noaaflag
        //let mut plus_args = Vec::new();

        trace!("options without dash:{:?}", without_dash);
        trace!("options with dash:{:?}", with_dash);

        //───────────────────────────────────────────────────────────────────────────────────
        // process the arguments not starting with a '-'
        //───────────────────────────────────────────────────────────────────────────────────
        for arg in without_dash {
            if let Some(s) = arg.strip_prefix('@') {
                options.protocol.server = s.to_string();
                continue;
            }

            // check if this is a domain (should include a dot)
            if arg.contains('.') {
                options.protocol.domain = arg.to_string();
                continue;
            }

            // manage + options
            // if arg.starts_with('+') && arg.len() > 1 {
            //     plus_args.push(PlusArg::new(&arg[1..]));
            //     continue;
            // }

            // otherwise it's a Qtype
            if let Ok(qt) = QType::from_str(arg.to_uppercase().as_str()) {
                options.protocol.qtype.push(qt);
                continue;
            }
        }

        // //───────────────────────────────────────────────────────────────────────────────────
        // // manage plus args
        // //───────────────────────────────────────────────────────────────────────────────────
        // trace!("plus args={:?}", plus_args);
        // let plus_map = PlusArgList::from(plus_args.as_slice());

        //───────────────────────────────────────────────────────────────────────────────────
        // now process the arguments starting with a '-'
        //───────────────────────────────────────────────────────────────────────────────────
        let matches = Command::new("DNS query tool")
            .version("0.1")
            .author("Alain Viguier dandyvica@gmail.com")
            .about(
                r#"A simple DNS query client
        
            Project home page: https://github.com/dandyvica/dqy
        
            "#,
            )
            .no_binary_name(true)
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
                    .default_value("A")
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
                Arg::new("port")
                    .short('p')
                    .long("port")
                    .long_help("Optional DNS port number. If not specified, default port for the transport will be used (e.g.: 853 for DoT).")
                    .action(ArgAction::Set)
                    .value_name("PORT")
                    .value_parser(clap::value_parser!(u16)),
            )
            .arg(
                Arg::new("4")
                    .short('4')
                    .long("ip4")
                    .long_help("Sets IP version 4. Only send queries to ipv4 enabled nameservers.")
                    .action(ArgAction::SetFalse)
                    .value_name("IPV4")
            )
            .arg(
                Arg::new("6")
                    .short('6')
                    .long("ip6")
                    .long_help("Sets IP version 6. Only send queries to ipv6 enabled nameservers.")
                    .action(ArgAction::SetTrue)
                    .value_name("IPV6")
            )
            .arg(
                Arg::new("tcp")
                    .short('T')
                    .long("tcp")
                    .long_help("Forces transport to TCP.")
                    .action(ArgAction::SetTrue)
            )
            .arg(
                Arg::new("tls")
                    .short('S')
                    .long("tls")
                    .long_help("Forces transport to DNS over TLS (DoT).")
                    .visible_aliases(["dot", "DoT"])
                    .action(ArgAction::SetTrue)
                    .value_name("TLS")
            )
            .arg(
                Arg::new("https")
                    .short('H')
                    .long("https")
                    .long_help("Sets transport to DNS over https (DoH).")
                    .visible_aliases(["doh", "DoH"])
                    .action(ArgAction::SetTrue)
                    .value_name("https")
            )
            .arg(
                Arg::new("stats")
                    .long("stats")
                    .long_help("Prints out statistics around the query.")
                    .action(ArgAction::SetTrue)
                    .value_name("STATS")
            )
            .arg(
                Arg::new("timeout")
                    .long("timeout")
                    .long_help("Sets the timeout for network operations (in ms).")
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(u64))
                    .default_value("5000")
                    .value_name("TIMEOUT")
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
                Arg::new("dnssec")
                    .long("dnssec")
                    .long_help("Sets DNSSEC bit flag in OPT record.")
                    .action(ArgAction::SetTrue)
                    .value_name("DNSSEC FLAG")
            )
            .arg(
                Arg::new("bufsize")
                    .long("bufsize")
                    .long_help("Sets the UDP message buffer size to BUFSIZE bytes in the OPT record.")
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(u16))
                    .value_name("BUFSIZE")
            )
            .arg(
                Arg::new("nsid")
                    .long("nsid")
                    .long_help("Sets the EDNS NSID option in the OPT record.")
                    .action(ArgAction::SetTrue)
            )
            .arg(
                Arg::new("padding")
                    .long("padding")
                    .long_help("Sets the EDNS Padding option in the OPT record to LENGTH.")
                    .action(ArgAction::Set)
                    .value_name("LENGTH")
                    .value_parser(clap::value_parser!(u16))
            )
            .arg(
                Arg::new("set")
                    .long("set")
                    .long_help("Sets flags in the query header.")
                    .action(ArgAction::Set)
                    .num_args(1..=6)
                    .value_name("FLAGS")
                    .value_parser(["aa", "ad", "cd", "ra", "rd", "tc"])
            )
            .arg(
                Arg::new("unset")
                    .long("unset")
                    .long_help("Unsets flags in the query header. If a flag is set and unset, unset wins.")
                    .action(ArgAction::Set)
                    .num_args(1..=6)
                    .value_name("FLAGS")
                    .value_parser(["aa", "ad", "cd", "ra", "rd", "tc"])
            )
            .arg(
                Arg::new("verbose")
                    .short('v')
                    .long("verbose")
                    .long_help("Verbose mode.")
                    .action(ArgAction::Count)
            )
            .arg(
                Arg::new("dau")
                    .long("dau")
                    .long_help("Sets the EDNS DAU option in the OPT record.")
                    .value_delimiter(',')
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(u8))
                    .num_args(1..=255)
                    .value_name("ALG-CODE")
            )
            .arg(
                Arg::new("dhu")
                    .long("dhu")
                    .long_help("Sets the EDNS DHU option in the OPT record.")
                    .value_delimiter(',')
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(u8))
                    .num_args(1..=255)
                    .value_name("ALG-CODE")
                    .value_parser(clap::value_parser!(u8))
            )
            .arg(
                Arg::new("n3u")
                    .long("n3u")
                    .long_help("Sets the EDNS N3U option in the OPT record.")
                    .value_delimiter(',')
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(u8))
                    .num_args(1..=255)
                    .value_name("ALG-CODE")
                    .value_parser(clap::value_parser!(u8))
            )
        .get_matches_from(with_dash);

        //───────────────────────────────────────────────────────────────────────────────────
        // QTypes, QClass
        //───────────────────────────────────────────────────────────────────────────────────
        if options.protocol.qtype.is_empty() {
            let vals: Vec<QType> = matches.get_many("type").unwrap().copied().collect();
            options.protocol.qtype = vals;
        }
        options.protocol.qclass = *matches.get_one::<QClass>("class").unwrap();

        //───────────────────────────────────────────────────────────────────────────────────
        // ip versions (V4 is by default)
        //───────────────────────────────────────────────────────────────────────────────────
        if matches.get_flag("6") {
            options.transport.ip_version = IPVersion::V6;
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // if no domain to query, by default set root (.)
        //───────────────────────────────────────────────────────────────────────────────────
        if options.protocol.domain.is_empty() {
            options.protocol.domain = if let Some(d) = matches.get_one::<String>("domain") {
                d.clone()
            } else {
                String::from(".")
            };
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // transport mode
        //───────────────────────────────────────────────────────────────────────────────────
        if matches.get_flag("tcp") || options.transport.tcp {
            options.transport.transport_mode = TransportMode::Tcp;
        }
        if matches.get_flag("tls") || options.transport.tls || options.transport.dot {
            options.transport.transport_mode = TransportMode::DoT;
        }
        if matches.get_flag("https") || options.transport.https || options.transport.doh {
            options.transport.transport_mode = TransportMode::DoH;
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // port number is depending on transport mode or use one specified with --port
        //───────────────────────────────────────────────────────────────────────────────────
        options.transport.port = *matches
            .get_one::<u16>("port")
            .unwrap_or(&options.transport.transport_mode.default_port());

        //───────────────────────────────────────────────────────────────────────────────────
        // build the list of SocketAddrs
        //───────────────────────────────────────────────────────────────────────────────────
        // no server provided
        if options.protocol.server.is_empty() {
            // fetch the resolvers
            let resolvers = ResolverList::new()?;

            // convert to a vector of SocketAddrs
            options.protocol.resolvers = resolvers.to_socketaddresses(options.transport.port);

            // DoT needs the server name
            if options.transport.transport_mode == TransportMode::DoT {
                options.protocol.server = resolvers[0].ip_list()[0].to_string();
            }
        }
        // a server name or ip address is provided: we need to buld the SocketAddr from either a dot address or a domain name
        // e.g.: 1.1.1.1 or ns1.google.com
        else {
            if options.transport.transport_mode != TransportMode::DoH {
                // build the SocketAddr
                let addr_s = format!("{}:{}", options.protocol.server, options.transport.port);
                let addr = addr_s.to_socket_addrs()?;

                // new to filter for either IPV4 or IPV6
                let sock_addr = if options.transport.ip_version == IPVersion::V4 {
                    addr.filter(|x| x.is_ipv4()).nth(0)
                } else {
                    addr.filter(|x| x.is_ipv6()).nth(0)
                };

                if sock_addr.is_none() {
                    return Err(err_internal!(CantCreateSocketAddress));
                }

                options.protocol.resolvers = vec![sock_addr.unwrap()];
            }
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // timeout
        //───────────────────────────────────────────────────────────────────────────────────
        options.transport.timeout =
            Duration::from_millis(*matches.get_one::<u64>("timeout").unwrap());

        //───────────────────────────────────────────────────────────────────────────────────
        // internal domain name processing (IDNA)
        //───────────────────────────────────────────────────────────────────────────────────
        if options.protocol.domain.len() != options.protocol.domain.chars().count() {
            options.protocol.domain =
                idna::domain_to_ascii(options.protocol.domain.as_str()).unwrap();
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // if reverse query, ignore all other options
        //───────────────────────────────────────────────────────────────────────────────────
        if let Some(ip) = matches.get_one::<String>("ptr") {
            // reverse query uses PTR
            options.protocol.qtype = vec![QType::PTR];
            options.protocol.qclass = QClass::IN;

            // try to convert to a valid IP address
            let addr = IpAddr::from_str(ip)?;

            if addr.is_ipv4() {
                let mut limbs: Vec<_> = ip.split('.').collect();
                limbs.reverse();
                options.protocol.domain = format!("{}.in-addr.arpa", limbs.join("."));
            } else {
                // get individual u8 values because an ipv6 address might omit a heading 0
                // ex: 2001:470:30:84:e276:63ff:fe72:3900 => 2001:0470:0030:84:e276:63ff:fe72:3900

                // this will convert to ["2001", "0470", "0030", "0084", "e276", "63ff", "fe72", "3900"]
                let split = ip
                    .split(":") // split accordsing to ":"
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
        // by default, we want recursive queries, other flags are unset
        options.flags.rdflag = true;

        // set
        if let Some(v) = matches.get_many::<String>("set") {
            let flags: Vec<_> = v.collect();
            options.flags.aaflag = flags.contains(&&"aa".to_string());
            options.flags.adflag = flags.contains(&&"ad".to_string());
            options.flags.cdflag = flags.contains(&&"cd".to_string());
            options.flags.raflag = flags.contains(&&"ra".to_string());
            options.flags.rdflag = flags.contains(&&"rd".to_string());
            options.flags.tcflag = flags.contains(&&"tc".to_string());
        }

        // unset
        if let Some(v) = matches.get_many::<String>("unset") {
            let flags: Vec<_> = v.collect();
            options.flags.aaflag = flags.contains(&&"aa".to_string());
            options.flags.adflag = flags.contains(&&"ad".to_string());
            options.flags.cdflag = flags.contains(&&"cd".to_string());
            options.flags.raflag = flags.contains(&&"ra".to_string());
            options.flags.rdflag = flags.contains(&&"rd".to_string());
            options.flags.tcflag = flags.contains(&&"tc".to_string());
        }
        trace!("options flags: {:?}", options.flags);

        //───────────────────────────────────────────────────────────────────────────────────
        // OPT record and options
        //───────────────────────────────────────────────────────────────────────────────────
        options.edns.nsid = matches.get_flag("nsid");
        options.edns.padding = matches.get_one::<u16>("padding").and_then(|v| Some(*v));

        options.edns.dau = if let Some(v) = matches.get_many::<u8>("dau") {
            Some(v.copied().collect::<Vec<u8>>())
        } else {
            None
        };

        options.edns.dhu = if let Some(v) = matches.get_many::<u8>("dhu") {
            Some(v.copied().collect::<Vec<u8>>())
        } else {
            None
        };

        options.edns.n3u = if let Some(v) = matches.get_many::<u8>("n3u") {
            Some(v.copied().collect::<Vec<u8>>())
        } else {
            None
        };

        //───────────────────────────────────────────────────────────────────────────────────
        // manage other misc. options
        //───────────────────────────────────────────────────────────────────────────────────
        options.display.stats = matches.get_flag("stats");

        // verbosity
        if matches.contains_id("verbose") {
            let level = match matches.get_count("verbose") {
                0 => log::LevelFilter::Off,
                1 => log::LevelFilter::Info,
                2 => log::LevelFilter::Warn,
                3 => log::LevelFilter::Error,
                4 => log::LevelFilter::Debug,
                5..=255 => log::LevelFilter::Trace,
            };

            env_logger::Builder::new().filter_level(level).init();
        }

        Ok(options)
    }
}

// value QTypes on the command line when using the -type option
fn validate_qtypes(s: &str) -> Result<QType, String> {
    let qt_upper = s.to_uppercase();
    let q = QType::from_str(&qt_upper);
    
    QType::from_str(&qt_upper)
        .map_err(|e| format!("can't convert value '{e}' to a valid query type"))
}

// // Initialize logger: either create it or use it
// fn init_logger(logfile: &str) -> DNSResult<()> {
//     // initialize logger
//     let writable = OpenOptions::new().create(true).append(true).open(logfile)?;

//     WriteLogger::init(
//         LevelFilter::Trace,
//         simplelog::ConfigBuilder::new()
//             .set_time_format_rfc3339()
//             // .set_time_format_custom(format_description!(
//             //     "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond]"
//             .build(),
//         writable,
//     )?;

//     Ok(())
// }

#[cfg(test)]
mod tests {
    use super::*;

    fn args_to_options(args: &str) -> DNSResult<CliOptions> {
        let args: Vec<_> = args
            .split_ascii_whitespace()
            .map(|a| a.to_string())
            .collect();
        CliOptions::options(&args)
    }

    #[test]
    fn empty() {
        let opts = args_to_options("");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.protocol.qtype, vec![QType::A]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain, ".");
        assert_eq!(opts.transport.ip_version, IPVersion::V4);
        assert_eq!(opts.transport.transport_mode, TransportMode::Udp);
    }

    #[test]
    fn with_domain1() {
        let opts = args_to_options("-d www.google.com");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.protocol.qtype, vec![QType::A]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain, "www.google.com");
        assert_eq!(opts.transport.ip_version, IPVersion::V4);
        assert_eq!(opts.transport.transport_mode, TransportMode::Udp);
    }

    #[test]
    fn with_domain2() {
        let opts = args_to_options("-t AAAA -c CH -d www.google.com");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.protocol.qtype, vec![QType::AAAA]);
        assert_eq!(opts.protocol.qclass, QClass::CH);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain, "www.google.com");
        assert_eq!(opts.transport.ip_version, IPVersion::V4);
        assert_eq!(opts.transport.transport_mode, TransportMode::Udp);
    }

    #[test]
    fn with_no_dash() {
        let opts = args_to_options("@1.1.1.1 A AAAA MX www.google.com");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.protocol.qtype, vec![QType::A, QType::AAAA, QType::MX]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain, "www.google.com");
        assert_eq!(opts.transport.ip_version, IPVersion::V4);
        assert_eq!(opts.transport.transport_mode, TransportMode::Udp);
    }

    #[test]
    fn with_ipv6() {
        let opts = args_to_options("@2606:4700:4700::1111 A AAAA MX www.google.com -6");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.protocol.qtype, vec![QType::A, QType::AAAA, QType::MX]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain, "www.google.com");
        assert_eq!(opts.transport.ip_version, IPVersion::V6);
        assert_eq!(opts.transport.transport_mode, TransportMode::Udp);
    }

    #[test]
    fn with_tcp() {
        let opts = args_to_options("@2606:4700:4700::1111 A AAAA MX www.google.com +tcp -6");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.protocol.qtype, vec![QType::A, QType::AAAA, QType::MX]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain, "www.google.com");
        assert_eq!(opts.transport.ip_version, IPVersion::V6);
        assert_eq!(opts.transport.transport_mode, TransportMode::Tcp);
    }

    #[test]
    fn with_ptr() {
        let opts = args_to_options("@1.1.1.1 A AAAA MX www.google.com --tcp -x 1.2.3.4");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.protocol.qtype, vec![QType::PTR]);
        assert_eq!(opts.protocol.qclass, QClass::IN);
        assert_eq!(opts.transport.port, 53);
        assert_eq!(&opts.protocol.domain, "4.3.2.1.in-addr.arpa");
        assert_eq!(opts.transport.ip_version, IPVersion::V4);
        assert_eq!(opts.transport.transport_mode, TransportMode::Tcp);
    }

    #[test]
    fn plus() {
        let opts = args_to_options("@1.1.1.1 A www.google.com +dnssec +cdflag +noaaflag");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert!(opts.edns.dnssec);
        assert!(opts.flags.cdflag);
        assert!(!opts.flags.aaflag);
    }
}
