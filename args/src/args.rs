//! Manage command line arguments here.
use std::str::FromStr;
use std::time::Duration;
use std::{
    fs::{File, OpenOptions},
    net::IpAddr,
};

use crate::plus;

use super::plus::PlusArg;

use clap::{Arg, ArgAction, Command};

//use simplelog::*;
use idna::punycode::encode_str;
use log::debug;

use dns::{
    error::DNSResult,
    network::transport::{IPVersion, TransportMode},
    rfc::{qclass::QClass, qtype::QType},
};

use resolver::resolver::Resolvers;

const UDP_PORT: &'static str = "53";

/// This structure holds the command line arguments.
#[derive(Debug, Default)]
pub struct CliOptions {
    pub qtype: Vec<QType>,
    pub qclass: QClass,
    pub resolvers: Vec<IpAddr>,
    pub port: u16,
    pub domain: String,
    //pub debug: bool,
    pub transport_mode: TransportMode,
    pub ip_version: IPVersion,
    pub timeout: Option<Duration>,
    pub stats: bool,

    // server is the name passed after @
    pub server: String,
}

// OPT specific options
// #[derive(Debug, Default)]
// pub struct OptOptions {
//     use_it: bool,
//     bufsize: u16,
// }

impl CliOptions {
    pub fn options(args: &[String]) -> DNSResult<Self> {
        // save all cli options into a structure
        let mut options = CliOptions::default();

        // split arguments into 2 sets: those not starting with a '-' which should be first
        // and the others
        let dash_pos = args.iter().position(|arg| arg.starts_with("-"));
        //println!("dash_pos={:?}", dash_pos);

        let (without_dash, with_dash) = match dash_pos {
            Some(pos) => (&args[0..pos], &args[pos..]),
            None => (&args[..], &[] as &[String]),
        };

        let mut plus_args = Vec::new();

        // println!("without_dash={:?}", without_dash);
        // println!("with_dash={:?}", with_dash);

        // process the arguments not starting with a '-'
        for arg in without_dash {
            // check if it's a name server
            if arg.starts_with('@') {
                options.resolvers = vec![IpAddr::from_str(&arg[1..])?];
                options.server = arg[1..].to_string();
                continue;
            }

            // check if this is a domain (should include a dot)
            if arg.contains(".") {
                options.domain = arg.to_string();
                continue;
            }

            // manage + options
            if arg.starts_with('+') {
                plus_args.push(PlusArg::new(arg));
            }

            // otherwise it's a Qtype
            if let Ok(qt) = QType::try_from(arg.to_uppercase().as_str()) {
                options.qtype.push(qt);
            }
        }
        //println!("plus args={:?}", plus_args);

        // now process the arguments starting with a '-'
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
                    .default_value(UDP_PORT)
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
                Arg::new("dot")
                    .short('D')
                    .long("dot")
                    .long_help("Set transport to DNS over TLS.")
                    .action(ArgAction::SetTrue)
                    .value_name("DOT"),
            )
            .arg(
                Arg::new("stats")
                    .short('S')
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
            //     Arg::new("no-edns")
            //         .long("no-edns")
            //         .long_help("Do not add an OPT record to the query.")
            //         .action(ArgAction::SetTrue)
            //         .value_name("NO-EDNS"),
            // )
            .get_matches_from(with_dash);

        // copy values into option struct
        if options.qtype.is_empty() {
            options
                .qtype
                .push(*matches.get_one::<QType>("type").unwrap());
        }
        options.qclass = *matches.get_one::<QClass>("class").unwrap();
        options.port = *matches.get_one::<u16>("port").unwrap();

        // ip versions
        if matches.get_flag("6") {
            options.ip_version = IPVersion::V6;
        }

        // test if we already fill-in the domain
        if options.domain.is_empty() {
            options.domain = if let Some(d) = matches.get_one::<String>("domain") {
                d.clone()
            } else {
                String::from(".")
            };
        }

        // // name server was not provided: so lookup system DNS config
        if options.resolvers.is_empty() {
            let resolvers = Resolvers::get_servers(None);

            if resolvers.is_err() {
                eprintln!("error {:?} fetching resolvers", resolvers.unwrap_err());
                std::process::exit(1);
            } else {
                options.resolvers = resolvers.unwrap().v4;
            }
        }

        // transport mode
        if matches.get_flag("tcp") {
            options.transport_mode = TransportMode::Tcp;
        }
        if matches.get_flag("dot") {
            options.transport_mode = TransportMode::DoT;
        }


        options.timeout = Some(Duration::from_millis(
            *matches.get_one::<u64>("timeout").unwrap(),
        ));

        // internal domain name processing
        // if options.domain.len() != options.domain.chars().count() {
        //     options.domain = format!("xn--{}", encode_str(options.domain.as_str()).unwrap());
        // }

        // if reverse query, ignore all others
        if let Some(ip) = matches.get_one::<String>("ptr") {
            // reverse query uses PTR
            options.qtype = vec![QType::PTR];

            // new to reverse numbers
            if options.ip_version == IPVersion::V4 {
                let mut limbs: Vec<_> = ip.split(".").collect();
                limbs.reverse();
                options.domain = format!("{}.in-addr.arpa", limbs.join("."));
            }
        }

        // manage other options
        options.stats = matches.get_flag("stats");

        // println!("options={:#?}", options);
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
        assert_eq!(opts.transport_mode, TransportType::Udp);
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
        assert_eq!(opts.transport_mode, TransportType::Udp);
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
        assert_eq!(opts.transport_mode, TransportType::Udp);
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
        assert_eq!(opts.transport_mode, TransportType::Udp);
    }

    #[test]
    fn with_ipv6() {
        let opts = args_to_options("@1.1.1.1 A AAAA MX www.google.com -6");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.qtype, vec![QType::A, QType::AAAA, QType::MX]);
        assert_eq!(opts.qclass, QClass::IN);
        assert_eq!(opts.port, 53);
        assert_eq!(&opts.domain, "www.google.com");
        assert_eq!(opts.ip_version, IPVersion::V6);
        assert_eq!(opts.transport_mode, TransportType::Udp);
    }

    #[test]
    fn with_tcp() {
        let opts = args_to_options("@1.1.1.1 A AAAA MX www.google.com -6 --tcp");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.qtype, vec![QType::A, QType::AAAA, QType::MX]);
        assert_eq!(opts.qclass, QClass::IN);
        assert_eq!(opts.port, 53);
        assert_eq!(&opts.domain, "www.google.com");
        assert_eq!(opts.ip_version, IPVersion::V6);
        assert_eq!(opts.transport_mode, TransportType::Tcp);
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
        assert_eq!(opts.transport_mode, TransportType::Tcp);
    }
}
