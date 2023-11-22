//! Manage command line arguments here.
use std::str::FromStr;
use std::{
    fs::{File, OpenOptions},
    net::IpAddr,
};
use std::time::Duration;

use clap::{Arg, ArgAction, Command};


//use simplelog::*;
use log::debug;
use idna::punycode::encode_str;

use dns::{
    error::DNSResult,
    network::{IPVersion, TransportType},
    rfc1035::{qclass::QClass, qtype::QType},
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
    pub trp_type: TransportType,
    pub ip_version: IPVersion,
    pub timeout: Option<Duration>
}

impl CliOptions {
    pub fn options(args: &[String]) -> DNSResult<Self> {
        // save all cli options into a structure
        let mut options = CliOptions::default();

        // split arguments into 2 sets: those not starting with a '-' which should be first
        // and the others
        let dash_pos = args.iter().position(|arg| arg.starts_with("-"));
        println!("dash_pos={:?}", dash_pos);

        let (without_dash, with_dash) = match dash_pos {
            Some(pos) => (&args[0..pos], &args[pos..]),
            None => (&args[..], &[] as &[String]),
        };

        println!("without_dash={:?}", without_dash);
        println!("with_dash={:?}", with_dash);

        // process the arguments not starting with a '-'
        for arg in without_dash {
            // check if it's a name server
            if arg.starts_with('@') {
                options.resolvers = vec![IpAddr::from_str(&arg[1..])?];
                continue;
            }

            // check if this is a domain (should include a dot)
            if arg.contains(".") {
                options.domain = arg.to_string();
                continue;
            }

            // otherwise it's a Qtype
            if let Ok(qt) = QType::from_str(&arg.to_uppercase()) {
                options.qtype.push(qt);
            }
        }

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
                        "query class as specified in RFC1035. Possible values: IN, CS, CH, HS.",
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
                    .long_help("domain name to query.")
                    .action(ArgAction::Set)
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
                Arg::new("timeout")
                    .long("timeout")
                    .long_help("Set timeout for network operations (in ms).")
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(u64))
                    .default_value("5000")
                    .value_name("TIMEOUT"),
            )
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

        if matches.get_flag("tcp") {
            options.trp_type = TransportType::Tcp;
        }

        // test if we already fill-in the domain
        if options.domain.is_empty() {
            options.domain = matches.get_one::<String>("domain").unwrap().clone();
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

        options.timeout = Some(Duration::from_millis(*matches.get_one::<u64>("timeout").unwrap()));

        // internal domain name processing
        if options.domain.len() != options.domain.chars().count() {
            options.domain = format!("xn--{}", encode_str(options.domain.as_str()).unwrap());
        }

        // // if name server is not provided, use the ones given by the OS
        // if matches.is_present("ns") {
        //     let ip = IpAddr::from_str(matches.value_of("ns").unwrap())?;
        //     options.ns = vec![ip];
        // } else {
        //     options.ns = get_stub_resolvers()?;
        // }

        // // domain is required
        // options.domain = String::from(matches.value_of("domain").unwrap());

        // // if QType is not present, defaults to A
        // if matches.is_present("qtype") {
        //     options.qtype = QType::from_str(&matches.value_of("qtype").unwrap().to_uppercase())?;
        // } else {
        //     options.qtype = QType::A;
        // }

        // get qclass
        // options.qclass = *matches.get_one::<QClass>("class").unwrap();

        // // get port
        // options.port = *matches.get_one::<u16>("port").unwrap();

        // // OPT meta RR
        // options.no_opt = matches.get_flag("no-opt");

        // // create logfile only if requested. Logfile is gathering a bunch of information used for debugging
        // options.debug = matches.get_flag("debug");
        // if options.debug {
        //     init_logger("dnsq.log")?;
        // }

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

// // try to get the DNS servers in the /etc/resolv.conf file
// // Extract those args starting with a +
// fn get_plus_args(args: &Vec<String>, options: &mut CliOptions) {
//     // extract those starting with +
//     let plus_args: Vec<_> = args.iter().filter(|&x| x.starts_with('+')).collect();
//     println!("plus_args={:?}", plus_args);

//     for plus_arg in plus_args {
//         match plus_arg.as_ref() {
//             "+aaonly" => options.plus_args.aaonly = true,
//             "+additional" => options.plus_args.additional = true,
//             &_ => {}
//         }
//     }
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
    fn with_domain1() {
        let opts = args_to_options("-d www.google.com");
        assert!(opts.is_ok());
        let opts = opts.unwrap();

        assert_eq!(opts.qtype, vec![QType::A]);
        assert_eq!(opts.qclass, QClass::IN);
        assert_eq!(opts.port, 53);
        assert_eq!(&opts.domain, "www.google.com");
        assert_eq!(opts.ip_version, IPVersion::V4);
        assert_eq!(opts.trp_type, TransportType::Udp);
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
        assert_eq!(opts.trp_type, TransportType::Udp);
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
        assert_eq!(opts.trp_type, TransportType::Udp);
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
        assert_eq!(opts.trp_type, TransportType::Udp);
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
        assert_eq!(opts.trp_type, TransportType::Tcp);
    }
}
