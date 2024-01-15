// the list of all options used on CLI
use std::net::SocketAddr;
use std::time::Duration;

use dns::rfc::{flags::BitFlags, qclass::QClass, qtype::QType};
use transport::protocol::{IPVersion, Protocol};

use http::*;

//────────────────────────────────────────────────────────────────────────────────────────────
// List of flags to set or not
//
// Useful: https://serverfault.com/questions/729025/what-are-all-the-flags-in-a-dig-response
//────────────────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default)]
pub struct QueryFlags {
    // AA = Authoritative Answer
    pub aa: bool,

    // AD = Authenticated Data (for DNSSEC only; indicates that the data was authenticated)
    pub ad: bool,

    // CD = Checking Disabled (DNSSEC only; disables checking at the receiving server)
    pub cd: bool,

    // RA = Recursion Available (if set, denotes recursive query support is available)
    pub ra: bool,

    // RD = Recursion Desired (set in a query and copied into the response if recursion is supported)
    pub rd: bool,

    // TC TrunCation (truncated due to length greater than that permitted on the transmission channel)
    pub tc: bool,

    // Z is unused but ...
    pub z: bool,
}

//───────────────────────────────────────────────────────────────────────────────────
// EDNS options
//───────────────────────────────────────────────────────────────────────────────────
// pub enum OptControl {
//     Off = 0,   // don't include OPT record
// }

#[derive(Debug, Default)]
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

    // if true, OPT is included
    pub no_opt: bool,
}

#[derive(Debug, Default)]
//───────────────────────────────────────────────────────────────────────────────────
// Transport options
//───────────────────────────────────────────────────────────────────────────────────
pub struct Transport {
    // UPD, TCP, DoH or DoT
    pub transport_mode: Protocol,

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

    // http version
    pub https_version: version::Version,

    // ip port destination (53 for udp/tcp, 853 for DoT, 443 for DoH)
    pub port: u16,
}

#[derive(Debug, Default)]
//───────────────────────────────────────────────────────────────────────────────────
// Protocol options: linked to the DNS protocol itself
//───────────────────────────────────────────────────────────────────────────────────
pub struct DnsProtocol {
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

    // iterative lookup
    pub trace: bool,

    // JSON output if true
    pub json: bool,
    pub json_pretty: bool,

    // true if we want the question in non-JSON print
    pub question: bool,
}

/// This structure holds the command line arguments.
#[derive(Debug, Default)]
pub struct CliOptions {
    // DNS protocol options
    pub protocol: DnsProtocol,

    // transport related
    pub transport: Transport,

    // all flags
    pub flags: BitFlags,

    // EDNS options
    pub edns: Edns,

    // Display options
    pub display: Display,
}
