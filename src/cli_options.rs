//! Manage command line arguments here.
use std::net::SocketAddr;

use log::trace;

use dnslib::dns::rfc::domain::ROOT;
use dnslib::dns::rfc::opt::cookie::COOKIE;
use dnslib::dns::rfc::opt::zoneversion::ZONEVERSION;
use dnslib::dns::rfc::{
    domain::{DomainName, ROOT_DOMAIN},
    opt::{
        //dau_dhu_n3u::{EdnsKeyTag, DAU, DHU, N3U},
        nsid::NSID,
        //opt_rr::OPT,
        padding::Padding,
    },
    qclass::QClass,
    qtype::QType,
    query::{MetaRR, Query},
    resource_record::OPT,
};

use crate::args::CliOptions;

// DNSSEC OK
const DNSSEC_FLAG: u16 = 0x8000;

//───────────────────────────────────────────────────────────────────────────────────
// EDNS options
//───────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default, Clone)]
pub struct EdnsOptions {
    // This option requests that DNSSEC records be sent by setting the DNSSEC OK (DO) bit in the OPT record in the
    // additional section of the query.
    pub dnssec: bool,

    // add NSID option if true
    pub nsid: bool,

    // add COOKIE option
    pub cookie: Option<String>,

    // add ZONEVERSION option if true
    pub zoneversion: bool,

    // padding if the form of +padding=20
    pub padding: Option<u16>,

    // DAU, DHU, N3U same process
    pub dau: Option<Vec<u8>>,
    pub dhu: Option<Vec<u8>>,
    pub n3u: Option<Vec<u8>>,

    // edns-key-tag
    pub keytag: Option<Vec<u16>>,

    // if true, OPT is included
    pub no_opt: bool,
}

//───────────────────────────────────────────────────────────────────────────────────
// Protocol options: linked to the DNS protocol itself
//───────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct DnsProtocolOptions {
    pub qtype: Vec<QType>,

    // Qclass is IN by default
    pub qclass: QClass,

    // list of resolvers found in the client machine
    pub resolvers: Vec<SocketAddr>,

    // domain name to query. IDNA domains are punycoded before being sent
    pub domain_string: String,

    // domain name but converted to a DomainName struct
    pub domain_name: DomainName,
}

impl Default for DnsProtocolOptions {
    fn default() -> Self {
        Self {
            qtype: Vec::new(),
            qclass: QClass::default(),
            resolvers: Vec::new(),
            domain_string: String::from(ROOT), // by default, query is NS and sent to root
            domain_name: ROOT_DOMAIN,
        }
    }
}

pub trait FromOptions<T> {
    fn from_options(options: &CliOptions, other: T) -> Option<Self>
    where
        Self: Sized;
}

impl FromOptions<u16> for OPT {
    //───────────────────────────────────────────────────────────────────────────────────
    // build OPT RR from the cli options
    //───────────────────────────────────────────────────────────────────────────────────
    fn from_options(options: &CliOptions, bufsize: u16) -> Option<Self> {
        let edns = &options.edns;

        // --no-opt
        if edns.no_opt {
            return None;
        }

        // create OPT record. flags is set for DNSSEC
        let mut opt = OPT::new(bufsize, if edns.dnssec { Some(DNSSEC_FLAG) } else { None });

        //───────────────────────────────────────────────────────────────────────────────
        // add OPT options according to cli options
        //───────────────────────────────────────────────────────────────────────────────

        // NSID
        if edns.nsid {
            opt.add_option(NSID::default());
        }

        // COOKIE
        if let Some(cookie) = &edns.cookie {
            opt.add_option(COOKIE::from(cookie.as_str()));
        }

        // padding
        if let Some(len) = edns.padding {
            opt.add_option(Padding::new(len));
        }

        // ZONEVERSION
        if edns.zoneversion {
            opt.add_option(ZONEVERSION::default());
        }

        // DAU, DHU & N3U
        // if let Some(list) = &edns.dau {
        //     opt.add_option(DAU::from(list.as_slice()));
        // }
        // if let Some(list) = &edns.dhu {
        //     opt.add_option(DHU::from(list.as_slice()));
        // }
        // if let Some(list) = &edns.n3u {
        //     opt.add_option(N3U::from(list.as_slice()));
        // }

        // edns-key-tag
        // if let Some(list) = &edns.keytag {
        //     opt.add_option(EdnsKeyTag::from(list.as_slice()));
        // }

        Some(opt)
    }
}

impl FromOptions<&QType> for Query {
    //───────────────────────────────────────────────────────────────────────────────────
    // build query from the cli options
    //───────────────────────────────────────────────────────────────────────────────────
    fn from_options(options: &CliOptions, qt: &QType) -> Option<Query> {
        //───────────────────────────────────────────────────────────────────────────────────
        // build the OPT record to be added in the additional section
        //───────────────────────────────────────────────────────────────────────────────────
        let opt = OPT::from_options(options, options.transport.bufsize);
        trace!("OPT record: {:#?}", &opt);

        //───────────────────────────────────────────────────────────────────────────────────
        // build Query
        //───────────────────────────────────────────────────────────────────────────────────
        let mut query = Query::build()
            .with_type(qt)
            .with_class(&options.protocol.qclass)
            .with_domain(&options.protocol.domain_name)
            .with_flags(&options.flags);

        //───────────────────────────────────────────────────────────────────────────────────
        // Reserve length if TCP or TLS
        //───────────────────────────────────────────────────────────────────────────────────
        if options.transport.transport_mode.uses_leading_length() {
            query = query.with_length();
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // Add OPT if any
        //───────────────────────────────────────────────────────────────────────────────────
        if let Some(opt) = opt {
            query = query.with_additional(MetaRR::OPT(opt));
        }
        trace!("Query record: {:#?}", &query);

        Some(query)
    }
}
