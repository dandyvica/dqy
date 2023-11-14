//! Manage command line arguments here.
use std::str::FromStr;
use std::{
    fs::{File, OpenOptions},
    net::IpAddr,
};

use clap::{Arg, ArgAction, Command};

//use simplelog::*;
use log::debug;

use dnslib::{
    error::DNSResult,
    rfc1035::{domain::DomainName, qclass::QClass, qtype::QType},
};

use crate::resolver::Resolver;

/// This structure holds the command line arguments.
#[derive(Debug, Default)]
pub struct CliOptions {
    pub qtype: Vec<QType>,
    pub qclass: QClass,
    pub resolvers: Vec<IpAddr>,
    pub port: u16,
    pub domain: String,
    //pub debug: bool,
}

impl CliOptions {
    pub fn options(args: &[String]) -> DNSResult<Self> {
        // save all cli options into a structure
        let mut options = CliOptions::default();

        options.resolvers = Resolver::servers(None)?;
        debug!("found resolvers: {:?}", options.resolvers);

        // split arguments into 2 sets: those not starting with a '-' which should be first
        // and the others
        let dash_pos = args.iter().position(|arg| arg.starts_with("-"));
        println!("dash_pos={:?}", dash_pos);

        let (without_dash, with_dash) = match dash_pos {
            Some(pos) => (&args[0..pos], &args[pos..]),
            None => (&args[..], &[] as &[String])
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
            if let Ok(qt) = QType::from_str(arg) {
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
                    .long_help("Resource record type to query")
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
            .get_matches_from(args);

        // copy values into option struct
        options.qtype.push(*matches.get_one::<QType>("type").unwrap());

        // // name server was not provided: so lookup system DNS config
        // if options.ns.is_empty() {
        //     options.ns = get_stub_resolvers()?;
        // }
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

// // builds a Command clap struct. Useful for unit tests
// fn build_command() -> Command {
//     let args = vec![
//         arg_positionals(),
//         arg_qclass(),
//         arg_debug(),
//         arg_port(),
//         arg_no_opt(),
//     ];

//     Command::new("DNS query tool")
//         .version("0.1")
//         .author("Alain Viguier dandyvica@gmail.com")
//         .about(
//             r#"A simple DNS query client

//     Project home page: https://github.com/dandyvica/dnsquery

//     "#,
//         )
//         .args(args)
// }

// // all those functions define each Arg clap flag or option

// // -qtype
// // fn arg_qtype() -> Arg {

// // --no-opt
// fn arg_no_opt() -> Arg {
//     Arg::new("no-opt")
//         .short('n')
//         .long("no-opt")
//         .long_help("No OPT RR is sent")
//         .action(ArgAction::SetTrue)
// }

// // --domain
// fn arg_positionals() -> Arg {
//     Arg::new("positionals").action(clap::ArgAction::Append)
// }

// // --qclass
// fn arg_qclass() -> Arg {

// }

// // --port
// fn arg_port() -> Arg {
//     Arg::new("port")
//         .short('p')
//         .long("port")
//         .long_help("DNS port number")
//         .value_name("PORT")
//         .default_value("53")
//         .value_parser(clap::value_parser!(u16))
// }

// // --debug
// fn arg_debug() -> Arg {
//     Arg::new("debug")
//         .short('d')
//         .long("debug")
//         .required(false)
//         .long_help("Debug mode: will trace into dnq.log")
//         .action(ArgAction::SetTrue)
// }

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
// #[cfg(target_family = "unix")]
// pub fn get_stub_resolvers() -> DNSResult<Vec<IpAddr>> {
//     const RESOLV_CONF_FILE: &'static str = "/etc/resolv.conf";

//     // read whole file, get rid of comments and extract DNS stubs
//     let resolv_conf = std::fs::read_to_string(RESOLV_CONF_FILE)?;

//     let stubs: Vec<_> = resolv_conf
//         .lines()
//         .filter(|line| line.trim().starts_with("nameserver"))
//         .filter_map(|addr| addr.split_ascii_whitespace().nth(1))
//         .map(|ip| IpAddr::from_str(ip).unwrap())
//         .collect();

//     println!("{:?}", stubs);

//     Ok(stubs)
// }

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

// // // manage positional arguments to extract qtype, ns and domain
// // fn manage_positionals(options: &mut CliOptions, pos: &[&str]) -> DNSResult<()> {
// //     for arg in pos {
// //         // DNS server is supposed to start with @
// //         if arg.starts_with("@") {
// //             // convert string to ip address
// //             let ip = IpAddr::from_str(&arg[1..])?;
// //             options.ns = vec![ip];
// //         } else if let Ok(qtype) = QType::from_str(arg) {
// //             options.qtype = qtype;
// //         } else {
// //             options.domain = String::from(*arg);
// //         }
// //     }

// //     Ok(())
// // }
