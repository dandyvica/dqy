//! Manage command line arguments here.
use std::net::{SocketAddr, ToSocketAddrs};
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

// List of flags to set or not
// Useful: https://serverfault.com/questions/729025/what-are-all-the-flags-in-a-dig-response
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

/// This structure holds the command line arguments.
#[derive(Debug, Default)]
pub struct CliOptions {
    //───────────────────────────────────────────────────────────────────────────────────
    // DNS protocol options
    //───────────────────────────────────────────────────────────────────────────────────
    pub qtype: Vec<QType>,

    // Qclass is IN by default
    pub qclass: QClass,

    // list of resolvers found in the client machine
    pub resolvers: Vec<SocketAddr>,

    // ip port destination (53 for udp/tcp, 853 for DoT, 443 for DoH)
    pub port: u16,

    // domain name to query. IDNA domains are punycoded before being sent
    pub domain: String,

    // server is the name passed after @
    pub server: String,

    //───────────────────────────────────────────────────────────────────────────────────
    // DNS protocol transport options
    //───────────────────────────────────────────────────────────────────────────────────
    // UPD, TCP, DoH or DoT
    pub transport_mode: TransportMode,

    // V4 or V6
    pub ip_version: IPVersion,

    // timeout for network operations
    pub timeout: Duration,

    // This option requests that DNSSEC records be sent by setting the DNSSEC OK (DO) bit in the OPT record in the
    // additional section of the query.
    pub dnssec: bool,

    pub resolver: String,

    //───────────────────────────────────────────────────────────────────────────────────
    // plus args could be also clap options
    //───────────────────────────────────────────────────────────────────────────────────
    pub short: bool,

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

    //───────────────────────────────────────────────────────────────────────────────────
    // all flags
    //───────────────────────────────────────────────────────────────────────────────────
    pub flags: QueryFlags,

    //───────────────────────────────────────────────────────────────────────────────────
    // EDNS options
    //───────────────────────────────────────────────────────────────────────────────────

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
        let mut plus_args = Vec::new();

        trace!("options without dash:{:?}", without_dash);
        trace!("options with dash:{:?}", with_dash);

        //───────────────────────────────────────────────────────────────────────────────────
        // process the arguments not starting with a '-'
        //───────────────────────────────────────────────────────────────────────────────────
        for arg in without_dash {
            if let Some(s) = arg.strip_prefix('@') {
                options.server = s.to_string();
                continue;
            }

            // check if this is a domain (should include a dot)
            if arg.contains('.') {
                options.domain = arg.to_string();
                continue;
            }

            // manage + options
            if arg.starts_with('+') && arg.len() > 1 {
                plus_args.push(PlusArg::new(&arg[1..]));
                continue;
            }

            // otherwise it's a Qtype
            if let Ok(qt) = QType::from_str(arg.to_uppercase().as_str()) {
                options.qtype.push(qt);
                continue;
            }
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // manage plus args
        //───────────────────────────────────────────────────────────────────────────────────
        trace!("plus args={:?}", plus_args);
        let plus_map = PlusArgList::from(plus_args.as_slice());

        //plus_arg_bool!(options, dnssec, plus_map);
        plus_arg_bool!(options, dnssec, plus_map);
        plus_arg_bool!(options, short, plus_map);

        options.bufsize = plus_map.get_value("bufsize", 1232);

        plus_arg_bool!(options, tcp, plus_map);
        plus_arg_bool!(options, tls, plus_map);
        plus_arg_bool!(options, dot, plus_map);
        plus_arg_bool!(options, https, plus_map);
        plus_arg_bool!(options, doh, plus_map);

        // flags
        plus_arg_bool!(options.flags, aaflag, plus_map);
        plus_arg_bool!(options.flags, adflag, plus_map);
        plus_arg_bool!(options.flags, cdflag, plus_map);
        plus_arg_bool!(options.flags, raflag, plus_map);

        options.flags.rdflag = true;
        plus_arg_bool!(options.flags, rdflag, plus_map);
        plus_arg_bool!(options.flags, tcflag, plus_map);

        //───────────────────────────────────────────────────────────────────────────────────
        // EDNS options
        //───────────────────────────────────────────────────────────────────────────────────
        // NSID: +nsid
        plus_arg_bool!(options, nsid, plus_map);

        // PADDING: +padding=15
        if plus_map.contains("padding") {
            options.padding = Some(plus_map.get_value("padding", 0));
        }

        // DAU, DHU, N3U: +dau=1,2,3
        if plus_map.contains("dau") {
            let list: Option<Vec<u8>> = plus_map["dau"].split(',');
            options.dau = list;
        }
        if plus_map.contains("dhu") {
            let list: Option<Vec<u8>> = plus_map["dhu"].split(',');
            options.dhu = list;
        }
        if plus_map.contains("n3u") {
            let list: Option<Vec<u8>> = plus_map["n3u"].split(',');
            options.n3u = list;
        }

        // edns-key-tag
        if plus_map.contains("keytag") {
            let list: Option<Vec<u16>> = plus_map["keytag"].split(',');
            options.keytag = list;
        }        

        //───────────────────────────────────────────────────────────────────────────────────
        // verbositiy without setting env variable
        //───────────────────────────────────────────────────────────────────────────────────
        if plus_map.contains_key("v") {
            env_logger::Builder::new()
                .filter_level(log::LevelFilter::Info)
                .init();
        } else if plus_map.contains_key("vv") || plus_map.contains_key("v2") {
            env_logger::Builder::new()
                .filter_level(log::LevelFilter::Warn)
                .init();
        } else if plus_map.contains_key("vvv") || plus_map.contains_key("v3") {
            env_logger::Builder::new()
                .filter_level(log::LevelFilter::Error)
                .init();
        } else if plus_map.contains_key("vvvv") || plus_map.contains_key("v4") {
            env_logger::Builder::new()
                .filter_level(log::LevelFilter::Debug)
                .init();
        } else if plus_map.contains_key("vvvvvv") || plus_map.contains_key("v5") {
            env_logger::Builder::new()
                .filter_level(log::LevelFilter::Trace)
                .init();
        }

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
                    .action(ArgAction::Set)
                    .value_name("TYPE")
                    .value_parser(clap::value_parser!(QType))
                    .default_value("A"),
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
                    .default_value("IN"),
            )
            .arg(
                Arg::new("domain")
                    .short('d')
                    .long("domain")
                    .long_help("Domain name to query.")
                    .action(ArgAction::Set)
                    .required(false)
                    .value_name("DOMAIN"),
            )
            .arg(
                Arg::new("port")
                    .short('p')
                    .long("port")
                    .long_help("DNS port number.")
                    .action(ArgAction::Set)
                    .value_name("PORT")
                    .value_parser(clap::value_parser!(u16)),
            )
            .arg(
                Arg::new("4")
                    .short('4')
                    .long("ip4")
                    .long_help("Set IP version 4.")
                    .action(ArgAction::SetFalse)
                    .value_name("IPV4"),
            )
            .arg(
                Arg::new("6")
                    .short('6')
                    .long("ip6")
                    .long_help("Set IP version 6.")
                    .action(ArgAction::SetTrue)
                    .value_name("IPV6"),
            )
            .arg(
                Arg::new("tcp")
                    .short('T')
                    .long("tcp")
                    .long_help("Set transport to TCP.")
                    .action(ArgAction::SetTrue)
                    .value_name("TCP"),
            )
            .arg(
                Arg::new("tls")
                    .short('S')
                    .long("tls")
                    .long_help("Set transport to DNS over TLS (DoT).")
                    .action(ArgAction::SetTrue)
                    .value_name("TLS"),
            )
            .arg(
                Arg::new("https")
                    .short('H')
                    .long("https")
                    .long_help("Set transport to DNS over https (DoH).")
                    .action(ArgAction::SetTrue)
                    .value_name("https"),
            )
            .arg(
                Arg::new("stats")
                    // .short('s')
                    .long("stats")
                    .long_help("Print out statistics around the query.")
                    .action(ArgAction::SetTrue)
                    .value_name("STATS"),
            )
            .arg(
                Arg::new("timeout")
                    .long("timeout")
                    .long_help("Set timeout for network operations (in ms).")
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(u64))
                    .default_value("5000")
                    .value_name("TIMEOUT"),
            )
            .arg(
                Arg::new("ptr")
                    .short('x')
                    .long("reverse")
                    .long_help("Reverse DNS lookup.")
                    .action(ArgAction::Set)
                    .value_name("PTR"),
            )
            // .arg(
            //     Arg::new("dnssec")
            //         .long("dnssec")
            //         .long_help("Set DNSSEC bit flag in OPT record.")
            //         .action(ArgAction::SetTrue)
            //         .value_name("DNSSEC FLAG"),
            // )
            .get_matches_from(with_dash);

        //───────────────────────────────────────────────────────────────────────────────────
        // QType, QClass
        //───────────────────────────────────────────────────────────────────────────────────
        if options.qtype.is_empty() {
            options
                .qtype
                .push(*matches.get_one::<QType>("type").unwrap());
        }
        options.qclass = *matches.get_one::<QClass>("class").unwrap();

        //───────────────────────────────────────────────────────────────────────────────────
        // ip versions (V4 is by default)
        //───────────────────────────────────────────────────────────────────────────────────
        if matches.get_flag("6") {
            options.ip_version = IPVersion::V6;
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // if no domain to query, by default set root (.)
        //───────────────────────────────────────────────────────────────────────────────────
        if options.domain.is_empty() {
            options.domain = if let Some(d) = matches.get_one::<String>("domain") {
                d.clone()
            } else {
                String::from(".")
            };
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // transport mode
        //───────────────────────────────────────────────────────────────────────────────────
        if matches.get_flag("tcp") || options.tcp {
            options.transport_mode = TransportMode::Tcp;
        }
        if matches.get_flag("tls") || options.tls || options.dot {
            options.transport_mode = TransportMode::DoT;
        }
        if matches.get_flag("https") || options.https || options.doh {
            options.transport_mode = TransportMode::DoH;
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // port number is depending on transport mode
        //───────────────────────────────────────────────────────────────────────────────────
        options.port = *matches
            .get_one::<u16>("port")
            .unwrap_or(&options.transport_mode.default_port());

        //───────────────────────────────────────────────────────────────────────────────────
        // build the list of SocketAddrs
        //───────────────────────────────────────────────────────────────────────────────────
        // no server provided
        if options.server.is_empty() {
            // fetch the resolvers
            let resolvers = ResolverList::new()?;

            // convert to a vector of SocketAddrs
            options.resolvers = resolvers.to_socketaddresses(options.port);

            // DoT needs the server name
            if options.transport_mode == TransportMode::DoT {
                options.server = resolvers[0].ip_list()[0].to_string();
            }
        }
        // a server name or ip address is provided: we need to buld the SocketAddr from either a dot address or a domain name
        // e.g.: 1.1.1.1 or ns1.google.com
        else {
            if options.transport_mode != TransportMode::DoH {
                // build the SocketAddr
                let addr_s = format!("{}:{}", options.server, options.port);
                let addr = addr_s.to_socket_addrs()?;

                // new to filter for either IPV4 or IPV6
                let sock_addr = if options.ip_version == IPVersion::V4 {
                    addr.filter(|x| x.is_ipv4()).nth(0)
                } else {
                    addr.filter(|x| x.is_ipv6()).nth(0)
                };

                if sock_addr.is_none() {
                    return Err(err_internal!(CantCreateSocketAddress));
                }

                options.resolvers = vec![sock_addr.unwrap()];
            }
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // timeout
        //───────────────────────────────────────────────────────────────────────────────────
        options.timeout = Duration::from_millis(*matches.get_one::<u64>("timeout").unwrap());

        //───────────────────────────────────────────────────────────────────────────────────
        // internal domain name processing (IDNA)
        //───────────────────────────────────────────────────────────────────────────────────
        if options.domain.len() != options.domain.chars().count() {
            options.domain = idna::domain_to_ascii(options.domain.as_str()).unwrap();
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // if reverse query, ignore all other options
        //───────────────────────────────────────────────────────────────────────────────────
        if let Some(ip) = matches.get_one::<String>("ptr") {
            // reverse query uses PTR
            options.qtype = vec![QType::PTR];

            // new to reverse numbers
            if options.ip_version == IPVersion::V4 {
                let mut limbs: Vec<_> = ip.split('.').collect();
                limbs.reverse();
                options.domain = format!("{}.in-addr.arpa", limbs.join("."));
            }
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // manage other misc. options
        //───────────────────────────────────────────────────────────────────────────────────
        options.stats = matches.get_flag("stats");

        Ok(options)
    }
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

        assert_eq!(opts.qtype, vec![QType::A]);
        assert_eq!(opts.qclass, QClass::IN);
        assert_eq!(opts.port, 53);
        assert_eq!(&opts.domain, ".");
        assert_eq!(opts.ip_version, IPVersion::V4);
        assert_eq!(opts.transport_mode, TransportMode::Udp);
    }

    #[test]
    fn with_domain1() {
        let opts = args_to_options("-d www.google.com");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.qtype, vec![QType::A]);
        assert_eq!(opts.qclass, QClass::IN);
        assert_eq!(opts.port, 53);
        assert_eq!(&opts.domain, "www.google.com");
        assert_eq!(opts.ip_version, IPVersion::V4);
        assert_eq!(opts.transport_mode, TransportMode::Udp);
    }

    #[test]
    fn with_domain2() {
        let opts = args_to_options("-t AAAA -c CH -d www.google.com");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.qtype, vec![QType::AAAA]);
        assert_eq!(opts.qclass, QClass::CH);
        assert_eq!(opts.port, 53);
        assert_eq!(&opts.domain, "www.google.com");
        assert_eq!(opts.ip_version, IPVersion::V4);
        assert_eq!(opts.transport_mode, TransportMode::Udp);
    }

    #[test]
    fn with_no_dash() {
        let opts = args_to_options("@1.1.1.1 A AAAA MX www.google.com");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.qtype, vec![QType::A, QType::AAAA, QType::MX]);
        assert_eq!(opts.qclass, QClass::IN);
        assert_eq!(opts.port, 53);
        assert_eq!(&opts.domain, "www.google.com");
        assert_eq!(opts.ip_version, IPVersion::V4);
        assert_eq!(opts.transport_mode, TransportMode::Udp);
    }

    #[test]
    fn with_ipv6() {
        let opts = args_to_options("@2606:4700:4700::1111 A AAAA MX www.google.com -6");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.qtype, vec![QType::A, QType::AAAA, QType::MX]);
        assert_eq!(opts.qclass, QClass::IN);
        assert_eq!(opts.port, 53);
        assert_eq!(&opts.domain, "www.google.com");
        assert_eq!(opts.ip_version, IPVersion::V6);
        assert_eq!(opts.transport_mode, TransportMode::Udp);
    }

    #[test]
    fn with_tcp() {
        let opts = args_to_options("@2606:4700:4700::1111 A AAAA MX www.google.com +tcp -6");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.qtype, vec![QType::A, QType::AAAA, QType::MX]);
        assert_eq!(opts.qclass, QClass::IN);
        assert_eq!(opts.port, 53);
        assert_eq!(&opts.domain, "www.google.com");
        assert_eq!(opts.ip_version, IPVersion::V6);
        assert_eq!(opts.transport_mode, TransportMode::Tcp);
    }

    #[test]
    fn with_ptr() {
        let opts = args_to_options("@1.1.1.1 A AAAA MX www.google.com --tcp -x 1.2.3.4");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.qtype, vec![QType::PTR]);
        assert_eq!(opts.qclass, QClass::IN);
        assert_eq!(opts.port, 53);
        assert_eq!(&opts.domain, "4.3.2.1.in-addr.arpa");
        assert_eq!(opts.ip_version, IPVersion::V4);
        assert_eq!(opts.transport_mode, TransportMode::Tcp);
    }

    #[test]
    fn plus() {
        let opts = args_to_options("@1.1.1.1 A www.google.com +dnssec +cdflag +noaaflag");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert!(opts.dnssec);
        assert!(opts.flags.cdflag);
        assert!(!opts.flags.aaflag);
    }
}
