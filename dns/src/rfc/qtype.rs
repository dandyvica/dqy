use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use colored::Colorize;
use serde::Serialize;

use enum_from::{EnumDisplay, EnumFromStr, EnumTryFrom};
use show::show::ToColor;
use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

#[allow(clippy::unnecessary_cast)]
// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    PartialEq,
    EnumFromStr,
    EnumTryFrom,
    EnumDisplay,
    ToNetwork,
    FromNetwork,
    Serialize,
)]
#[repr(u16)]
#[from_network(TryFrom)]
pub enum QType {
    #[default]
    A = 1, // a host address	[RFC1035]
    NS = 2,          // an authoritative name server	[RFC1035]
    MD = 3,          // a mail destination (OBSOLETE - use MX)	[RFC1035]
    MF = 4,          // a mail forwarder (OBSOLETE - use MX)	[RFC1035]
    CNAME = 5,       // the canonical name for an alias	[RFC1035]
    SOA = 6,         // marks the start of a zone of authority	[RFC1035]
    MB = 7,          // a mailbox domain name (EXPERIMENTAL)	[RFC1035]
    MG = 8,          // a mail group member (EXPERIMENTAL)	[RFC1035]
    MR = 9,          // a mail rename domain name (EXPERIMENTAL)	[RFC1035]
    NULL = 10,       // a null RR (EXPERIMENTAL)	[RFC1035]
    WKS = 11,        // a well known service description	[RFC1035]
    PTR = 12,        // a domain name pointer	[RFC1035]
    HINFO = 13,      // host information	[RFC1035]
    MINFO = 14,      // mailbox or mail list information	[RFC1035]
    MX = 15,         // mail exchange	[RFC1035]
    TXT = 16,        // text strings	[RFC1035]
    RP = 17,         // for Responsible Person	[RFC1183]
    AFSDB = 18,      // for AFS Data Base location	[RFC1183][RFC5864]
    X25 = 19,        // for X.25 PSDN address	[RFC1183]
    ISDN = 20,       // for ISDN address	[RFC1183]
    RT = 21,         // for Route Through	[RFC1183]
    NSAP = 22,       // for NSAP address, NSAP style A record	[RFC1706]
    NSAPPTR = 23,    // for domain name pointer, NSAP style	[RFC1706]
    SIG = 24,        // for security signature	[RFC2536][RFC2931][RFC3110][RFC4034]
    KEY = 25,        // for security key	[RFC2536][RFC2539][RFC3110][RFC4034]
    PX = 26,         // X.400 mail mapping information	[RFC2163]
    GPOS = 27,       // Geographical Position	[RFC1712]
    AAAA = 28,       // IP6 Address	[RFC3596]
    LOC = 29,        // Location Information	[RFC1876]
    NXT = 30,        // Next Domain (OBSOLETE)	[RFC2535][RFC3755]
    EID = 31, // Endpoint Identifier	[Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]		1995-06
    NIMLOC = 32, // Nimrod Locator	[1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]		1995-06
    SRV = 33,    // Server Selection	[1][RFC2782]
    ATMA = 34, // ATM Address	[ ATM Forum Technical Committee, "ATM Name System, V2.0", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]
    NAPTR = 35, // Naming Authority Pointer	[RFC3403]
    KX = 36,   // Key Exchanger	[RFC2230]
    CERT = 37, // CERT	[RFC4398]
    A6 = 38,   // A6 (OBSOLETE - use AAAA)	[RFC2874][RFC3226][RFC6563]
    DNAME = 39, // DNAME	[RFC6672]
    SINK = 40, // SINK	[Donald_E_Eastlake][draft-eastlake-kitchen-sink]		1997-11
    OPT = 41,  // OPT	[RFC3225][RFC6891]
    APL = 42,  // APL	[RFC3123]
    DS = 43,   // Delegation Signer	[RFC4034]
    SSHFP = 44, // SSH Key Fingerprint	[RFC4255]
    IPSECKEY = 45, // IPSECKEY	[RFC4025]
    RRSIG = 46, // RRSIG	[RFC4034]
    NSEC = 47, // NSEC	[RFC4034][RFC9077]
    DNSKEY = 48, // DNSKEY	[RFC4034]
    DHCID = 49, // DHCID	[RFC4701]
    NSEC3 = 50, // NSEC3	[RFC5155][RFC9077]
    NSEC3PARAM = 51, // NSEC3PARAM	[RFC5155]
    TLSA = 52, // TLSA	[RFC6698]
    SMIMEA = 53, // S/MIME cert association	[RFC8162]	SMIMEA/smimea-completed-template	2015-12-01
    // Unassigned = 54, //
    HIP = 55,        // Host Identity Protocol	[RFC8005]
    NINFO = 56,      // NINFO	[Jim_Reid]	NINFO/ninfo-completed-template	2008-01-21
    RKEY = 57,       // RKEY	[Jim_Reid]	RKEY/rkey-completed-template	2008-01-21
    TALINK = 58, // Trust Anchor LINK	[Wouter_Wijngaards]	TALINK/talink-completed-template	2010-02-17
    CDS = 59,    // Child DS	[RFC7344]	CDS/cds-completed-template	2011-06-06
    CDNSKEY = 60, // DNSKEY(s) the Child wants reflected in DS	[RFC7344]		2014-06-16
    OPENPGPKEY = 61, // OpenPGP Key	[RFC7929]	OPENPGPKEY/openpgpkey-completed-template	2014-08-12
    CSYNC = 62,  // Child-To-Parent Synchronization	[RFC7477]		2015-01-27
    ZONEMD = 63, // Message Digest Over Zone Data	[RFC8976]	ZONEMD/zonemd-completed-template	2018-12-12
    SVCB = 64, // Service Binding	[draft-ietf-dnsop-svcb-https-00]	SVCB/svcb-completed-template	2020-06-30
    HTTPS = 65, // HTTPS Binding	[draft-ietf-dnsop-svcb-https-00]	HTTPS/https-completed-template	2020-06-30
    // Unassigned	66-98
    SPF = 99,     // [RFC7208]
    UINFO = 100,  // [IANA-Reserved]
    UID = 101,    // [IANA-Reserved]
    GID = 102,    // [IANA-Reserved]
    UNSPEC = 103, // [IANA-Reserved]
    NID = 104,    // [RFC6742]	ILNP/nid-completed-template
    L32 = 105,    // [RFC6742]	ILNP/l32-completed-template
    L64 = 106,    // [RFC6742]	ILNP/l64-completed-template
    LP = 107,     // [RFC6742]	ILNP/lp-completed-template
    EUI48 = 108,  // an EUI-48 address	[RFC7043]	EUI48/eui48-completed-template	2013-03-27
    EUI64 = 109,  // an EUI-64 address	[RFC7043]	EUI64/eui64-completed-template	2013-03-27
    // Unassigned	110-248
    TKEY = 249,     // Transaction Key	[RFC2930]
    TSIG = 250,     // Transaction Signature	[RFC8945]
    IXFR = 251,     // incremental transfer	[RFC1995]
    AXFR = 252,     // transfer of an entire zone	[RFC1035][RFC5936]
    MAILB = 253,    // mailbox-related RRs (MB, MG or MR)	[RFC1035]
    MAILA = 254,    // mail agent RRs (OBSOLETE - see MX)	[RFC1035]
    ANY = 255, // A request for some or all records the server has available	[RFC1035][RFC6895][RFC8482]
    URI = 256, // URI	[RFC7553]	URI/uri-completed-template	2011-02-22
    CAA = 257, // Certification Authority Restriction	[RFC8659]	CAA/caa-completed-template	2011-04-07
    AVC = 258, // Application Visibility and Control	[Wolfgang_Riedel]	AVC/avc-completed-template	2016-02-26
    DOA = 259, // Digital Object Architecture	[draft-durand-doa-over-dns]	DOA/doa-completed-template	2017-08-30
    AMTRELAY = 260, // Automatic Multicast Tunneling Relay	[RFC8777]	AMTRELAY/amtrelay-completed-template	2019-02-06
    // Unassigned	261-32767
    TA = 32768, // DNSSEC Trust Authorities	[Sam_Weiler][http://cameo.library.cmu.edu/][ Deploying DNSSEC Without a Signed Root. Technical Report 1999-19, Information Networking Institute, Carnegie Mellon University, April 2004.]		2005-12-13
    DLV = 32769, // DNSSEC Lookaside Validation (OBSOLETE)	[RFC8749][RFC4431]

    #[fallback]
    TYPE(u16),
}

impl ToColor for QType {
    fn to_color(&self) -> colored::ColoredString {
        self.to_string().bright_blue()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{from_network_test, to_network_test};

    #[test]
    fn conversion() {
        use std::str::FromStr;

        // from_str
        let qt = QType::from_str("A").unwrap();
        assert_eq!(qt, QType::A);
        let qt = QType::from_str("foo").unwrap_err();
        assert_eq!(qt, format!("no variant corresponding to value 'foo'"));
        let qt = QType::from_str("TYPE1234").unwrap();
        assert_eq!(qt, QType::TYPE(1234));
        let qt = QType::from_str("TYPEA234").unwrap_err();
        assert_eq!(qt, format!("no variant corresponding to value 'TYPEA234'"));

        // try_from
        let qt = QType::try_from(4u16).unwrap();
        assert_eq!(qt, QType::MF);
        let qt = QType::try_from(1000u16).unwrap();
        assert_eq!(qt, QType::TYPE(1000));

        // display
        let qt = QType::from_str("TSIG").unwrap();
        assert_eq!(&qt.to_string(), "TSIG");
        let qt = QType::try_from(2u16).unwrap();
        assert_eq!(&qt.to_string(), "NS");
        let qc = QType::try_from(1000u16).unwrap();
        assert_eq!(&qc.to_string(), "TYPE1000");
        let qt = QType::from_str("TYPE1234").unwrap();
        assert_eq!(&qt.to_string(), "TYPE1234");
    }

    #[test]
    fn network() {
        let q = QType::AAAA;
        to_network_test(&q, 2, &[0x00, 28]);
        from_network_test(None, &q, &vec![0x00, 28]);

        let q = QType::TYPE(0xFFFE);
        to_network_test(&q, 2, &[0xFF, 0xFE]);
        from_network_test(None, &q, &vec![0xFF, 0xFE]);
    }
}
