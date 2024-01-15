//! Manage command line arguments here.
use std::net::SocketAddr;

use dns::rfc::{qclass::QClass, qtype::QType};

//────────────────────────────────────────────────────────────────────────────────────────────
// List of flags to set or not
//
// Useful: https://serverfault.com/questions/729025/what-are-all-the-flags-in-a-dig-response
//────────────────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default)]
pub struct QueryFlagsOptions {
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
pub struct EdnsOptions {
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

//───────────────────────────────────────────────────────────────────────────────────
// Protocol options: linked to the DNS protocol itself
//───────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default)]
pub struct DnsProtocolOptions {
    pub qtype: Vec<QType>,

    // Qclass is IN by default
    pub qclass: QClass,

    // list of resolvers found in the client machine
    pub resolvers: Vec<SocketAddr>,

    // domain name to query. IDNA domains are punycoded before being sent
    pub domain: String,
    // server is the name passed after @
    //pub server: String,
}

//───────────────────────────────────────────────────────────────────────────────────
// Display options
//───────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default)]
pub struct DisplayOptions {
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
