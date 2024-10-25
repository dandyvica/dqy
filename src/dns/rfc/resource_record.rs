use std::{fmt, io::Cursor, net::IpAddr};

use colored::Colorize;
use serde::Serialize;
use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use super::{
    a::A, aaaa::AAAA, cname::CNAME, dnskey::DNSKEY, domain::DomainName, hinfo::HINFO, loc::LOC,
    mx::MX, ns::NS, ptr::PTR, qclass::QClass, qtype::QType, rdata::RData, soa::SOA, txt::TXT,
};
use crate::show::{ShowOptions, ToColor};

use crate::dns::{
    buffer::Buffer,
    rfc::{
        afsdb::AFSDB,
        apl::APL,
        caa::CAA,
        cert::CERT,
        cname::DNAME,
        csync::CSYNC,
        dhcid::DHCID,
        dnskey::CDNSKEY,
        ds::{CDS, DLV, DS},
        eui48::EUI48,
        eui64::EUI64,
        hip::HIP,
        ipseckey::IPSECKEY,
        kx::KX,
        naptr::NAPTR,
        nsec::NSEC,
        nsec3::NSEC3,
        nsec3param::NSEC3PARAM,
        openpgpkey::OPENPGPKEY,
        opt::opt_rr::OptOption,
        rp::RP,
        rrsig::RRSIG,
        srv::SRV,
        sshfp::SSHFP,
        svcb::{HTTPS, SVCB},
        tlsa::{SMIMEA, TLSA},
        uri::URI,
        zonemd::ZONEMD,
    },
};

use log::{debug, trace};

// 4.1.3. Resource record format

// The answer, authority, and additional sections all share the same
// format: a variable number of resource records, where the number of
// records is specified in the corresponding count field in the header.
// Each resource record has the following format:
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                                               |
//     /                                               /
//     /                      NAME                     /
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TYPE                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     CLASS                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TTL                      |
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                   RDLENGTH                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//     /                     RDATA                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// OPT definition: https://datatracker.ietf.org/doc/html/rfc6891#section-6.1
// +------------+--------------+------------------------------+
// | Field Name | Field Type   | Description                  |
// +------------+--------------+------------------------------+
// | NAME       | domain name  | MUST be 0 (root domain)      |
// | TYPE       | u_int16_t    | OPT (41)                     |
// | CLASS      | u_int16_t    | requestor's UDP payload size |
// | TTL        | u_int32_t    | extended RCODE and flags     |
// | RDLEN      | u_int16_t    | length of all RDATA          |
// | RDATA      | octet stream | {attribute,value} pairs      |
// +------------+--------------+------------------------------+

// When a RR is a standard RR (not a pseudo or meta-RR)
#[derive(Debug, Default, PartialEq, ToNetwork, FromNetwork)]
pub struct RegularClassTtl {
    pub(super) class: QClass,
    pub(super) ttl: u32,
}

// Case of OPT RR
#[derive(Debug, Default, PartialEq, ToNetwork, FromNetwork)]
pub struct OptPayload {
    pub(super) payload: u16,
    pub(super) extended_rcode: u8,
    pub(super) version: u8,
    pub(super) flags: u16,
}

#[derive(Debug, ToNetwork)]
// CLASS & TTL vary if RR is OPT or not
#[derive(PartialEq)]
pub enum OptOrClassTtl {
    Regular(RegularClassTtl),
    Opt(OptPayload),
}

impl OptOrClassTtl {
    // return the regular struct
    pub fn regular(&self) -> Option<&RegularClassTtl> {
        if let OptOrClassTtl::Regular(x) = self {
            Some(x)
        } else {
            None
        }
    }

    // return the OPT struct
    pub fn opt(&self) -> Option<&OptPayload> {
        if let OptOrClassTtl::Opt(x) = self {
            Some(x)
        } else {
            None
        }
    }
}

impl Default for OptOrClassTtl {
    fn default() -> Self {
        Self::Regular(RegularClassTtl::default())
    }
}

impl fmt::Display for OptOrClassTtl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptOrClassTtl::Regular(x) => write!(f, "{:<10} {:<10}", x.class.to_string(), x.ttl),
            OptOrClassTtl::Opt(x) => write!(
                f,
                "{} {} {} {}",
                x.payload, x.extended_rcode, x.version, x.flags
            ),
        }
    }
}

// Custom serialization
use serde::{ser::SerializeMap, Serializer};
impl Serialize for OptOrClassTtl {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            OptOrClassTtl::Regular(x) => {
                let mut seq = serializer.serialize_map(Some(2))?;
                seq.serialize_entry("class", &x.class)?;
                seq.serialize_entry("ttl", &x.ttl)?;
                seq.end()
            }
            OptOrClassTtl::Opt(x) => {
                let mut seq = serializer.serialize_map(Some(4))?;
                seq.serialize_entry("payload", &x.payload)?;
                seq.serialize_entry("extended_rcode", &x.extended_rcode)?;
                seq.serialize_entry("version", &x.version)?;
                seq.serialize_entry("flags", &x.flags)?;
                seq.end()
            }
        }
    }
}

// a new type definition for printing out TTL as days, hours, minutes and seconds
struct Ttl(u32);

impl fmt::Display for Ttl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ttl = self.0;

        let days = ttl / (60 * 60 * 24);
        ttl -= days * (60 * 60 * 24);
        let hours = ttl / (60 * 60);
        ttl -= hours * (60 * 60);
        let minutes = ttl / 60;
        let seconds = ttl - minutes * 60;

        if days != 0 {
            write!(f, "{}d{}h{}m{}s", days, hours, minutes, seconds)?;
        } else if hours != 0 {
            write!(f, "{}h{}m{}s", hours, minutes, seconds)?;
        } else if minutes != 0 {
            write!(f, "{}m{}s", minutes, seconds)?;
        } else {
            write!(f, "{}s", seconds)?;
        }

        Ok(())
    }
}

impl ToColor for Ttl {
    fn to_color(&self) -> colored::ColoredString {
        self.to_string().bright_red()
    }
}

#[derive(Debug, Default, ToNetwork, Serialize)]
pub struct ResourceRecord {
    pub name: DomainName, // an owner name, i.e., the name of the node to which this resource record pertains.
    pub r#type: QType,    // two octets containing one of the RR TYPE codes.

    // pub class: EitherOr<QClass, u16>, // two octets containing one of the RR CLASS codes or payload size in case of OPT
    // pub ttl: EitherOr<u32, OptTTL>,
    #[serde(flatten)]
    pub opt_or_class_ttl: OptOrClassTtl,
    // a bit = 32 signed (actually unsigned) integer that specifies the time interval
    // that the resource record may be cached before the source
    // of the information should again be consulted. Zero
    // values are interpreted to mean that the RR can only be
    // used for the transaction in progress, and should not be
    // cached.  For example, SOA records are always distributed
    // with a zero TTL to prohibit caching.  Zero values can
    // also be used for extremely volatile data.
    pub(super) rd_length: u16, // an unsigned 16 bit integer that specifies the length in octets of the RDATA field.

    #[serde(flatten)]
    pub(super) r_data: RData,
    //  a variable length string of octets that describes the
    //  resource.  The format of this information varies
    //  according to the TYPE and CLASS of the resource record.
}

impl ResourceRecord {
    // return the domain name when rr is NS
    pub fn ns_name(&self) -> Option<DomainName> {
        if self.r#type == QType::NS {
            if let RData::NS(ns) = &self.r_data {
                return Some(ns.0.clone());
            }
        }
        None
    }

    // in case of A or AAAA addresses, returns the ip address (either V4 or V6) from the RData
    pub fn ip_address(&self) -> Option<IpAddr> {
        match self.r#type {
            QType::A => {
                if let RData::A(ip4) = &self.r_data {
                    return Some(IpAddr::from(ip4.0));
                }
            }
            QType::AAAA => {
                if let RData::AAAA(ip6) = &self.r_data {
                    return Some(IpAddr::from(ip6.0));
                }
            }
            _ => return None,
        }
        None
    }
}

impl fmt::Display for ResourceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<28} {:<10} {} {:<10}",
            self.name.to_string(),
            self.r#type.to_string(),
            // self.class.to_string(),
            // self.ttl.to_string(),
            self.opt_or_class_ttl,
            self.rd_length
        )?;

        if self.rd_length != 0 {
            write!(f, "{}", self.r_data)?;
        }

        Ok(())
    }
}

// standard lengths for displaying and aligning a RR
const NAME: usize = 28;
const TYPE: usize = 10;
const LENGTH: usize = 5;
const CLASS: usize = 4;
const TTL_INT: usize = 7;
const TTL_STRING: usize = 12;

// don't use Show trait to provide extra length used to align output
// use this function
impl ResourceRecord {
    // local function to print out RR
    fn display(&self, fmt: &str, raw_ttl: bool, name_length: usize) {
        for f in fmt.split(",") {
            match f.trim() {
                "name" => print!("{:<name_length$} ", self.name.to_color()),
                "type" => print!("{:<TYPE$} ", self.r#type.to_color()),
                "length" => print!("{:<LENGTH$} ", self.rd_length),
                "class" => {
                    if let Some(r) = self.opt_or_class_ttl.regular() {
                        print!("{:<CLASS$} ", r.class.to_string())
                    }
                }
                "ttl" => {
                    if let Some(r) = self.opt_or_class_ttl.regular() {
                        if raw_ttl {
                            print!("{:<TTL_INT$} ", r.ttl)
                        } else {
                            print!("{:<TTL_STRING$} ", Ttl(r.ttl).to_color())
                        }
                    }
                }
                "rdata" => print!("{}", self.r_data.to_color()),
                _ => (),
            }
        }
    }

    pub(super) fn show(&self, display_options: &ShowOptions, length: Option<usize>) {
        let name_length = length.unwrap_or(NAME);

        // formatting display
        if !display_options.fmt.is_empty() {
            self.display(&display_options.fmt, display_options.raw_ttl, name_length);
            println!();
            return;
        }

        // other options
        if display_options.short {
            println!("{}", self.r_data);
        } else if self.r#type != QType::OPT {
            const ALL_FIELDS: &str = "name,type, length,class,ttl,length,rdata";
            self.display(ALL_FIELDS, display_options.raw_ttl, name_length);
            println!();
        } else {
            println!("OPT");
        }
    }
}

// Macro used to ease the ResourceRecord implementation of the FromNetworkOrder trait
macro_rules! get_rr {
    // to deserialize "simple" structs (like A)
    ($buffer:ident, $t:ty, $arm:path) => {{
        let mut x = <$t>::default();
        x.deserialize_from($buffer)?;
        $arm(x)
    }};

    // to deserialize "complex" structs (like DNSKEY)
    ($buffer:ident, $t:ty, $arm:path, $e:expr) => {{
        let mut x = <$t>::new($e);
        x.deserialize_from($buffer)?;
        $arm(x)
    }};
}

impl<'a> FromNetworkOrder<'a> for ResourceRecord {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        self.name.deserialize_from(buffer)?;
        self.r#type.deserialize_from(buffer)?;

        // OPT or a regular RR ?
        self.opt_or_class_ttl = if self.r#type == QType::OPT {
            get_rr!(buffer, OptPayload, OptOrClassTtl::Opt)
        } else {
            get_rr!(buffer, RegularClassTtl, OptOrClassTtl::Regular)
        };

        self.rd_length.deserialize_from(buffer)?;

        debug!(
            "found RR: type:{:?} name:<{}> class-ttl/opt:{} RD_length:{}",
            self.r#type, self.name, self.opt_or_class_ttl, self.rd_length
        );

        if self.rd_length != 0 {
            match self.r#type {
                // RData enum
                QType::A => self.r_data = get_rr!(buffer, A, RData::A),
                QType::AAAA => self.r_data = get_rr!(buffer, AAAA, RData::AAAA),
                QType::AFSDB => self.r_data = get_rr!(buffer, AFSDB, RData::AFSDB),
                QType::APL => self.r_data = get_rr!(buffer, APL, RData::APL, self.rd_length),
                QType::CDNSKEY => {
                    self.r_data = get_rr!(buffer, CDNSKEY, RData::CDNSKEY, self.rd_length)
                }
                QType::CAA => self.r_data = get_rr!(buffer, CAA, RData::CAA, self.rd_length),
                QType::CDS => self.r_data = get_rr!(buffer, CDS, RData::CDS, self.rd_length),
                QType::CERT => self.r_data = get_rr!(buffer, CERT, RData::CERT, self.rd_length),
                QType::CNAME => self.r_data = get_rr!(buffer, CNAME, RData::CNAME),
                QType::CSYNC => self.r_data = get_rr!(buffer, CSYNC, RData::CSYNC, self.rd_length),
                QType::DHCID => self.r_data = get_rr!(buffer, DHCID, RData::DHCID, self.rd_length),
                QType::DNAME => self.r_data = get_rr!(buffer, DNAME, RData::DNAME),
                QType::DLV => self.r_data = get_rr!(buffer, DLV, RData::DLV, self.rd_length),
                QType::DNSKEY => {
                    self.r_data = get_rr!(buffer, DNSKEY, RData::DNSKEY, self.rd_length)
                }
                QType::DS => self.r_data = get_rr!(buffer, DS, RData::DS, self.rd_length),
                QType::EUI48 => self.r_data = get_rr!(buffer, EUI48, RData::EUI48),
                QType::EUI64 => self.r_data = get_rr!(buffer, EUI64, RData::EUI64),
                QType::HINFO => self.r_data = get_rr!(buffer, HINFO, RData::HINFO),
                QType::HIP => self.r_data = get_rr!(buffer, HIP, RData::HIP, self.rd_length),
                QType::HTTPS => self.r_data = get_rr!(buffer, HTTPS, RData::HTTPS, self.rd_length),
                QType::IPSECKEY => {
                    self.r_data = get_rr!(buffer, IPSECKEY, RData::IPSECKEY, self.rd_length)
                }
                QType::KX => self.r_data = get_rr!(buffer, KX, RData::KX),
                QType::LOC => self.r_data = get_rr!(buffer, LOC, RData::LOC),
                QType::MX => self.r_data = get_rr!(buffer, MX, RData::MX),
                QType::NAPTR => self.r_data = get_rr!(buffer, NAPTR, RData::NAPTR),
                QType::NS => self.r_data = get_rr!(buffer, NS, RData::NS),
                QType::NSEC => self.r_data = get_rr!(buffer, NSEC, RData::NSEC, self.rd_length),
                QType::NSEC3 => self.r_data = get_rr!(buffer, NSEC3, RData::NSEC3, self.rd_length),
                QType::NSEC3PARAM => self.r_data = get_rr!(buffer, NSEC3PARAM, RData::NSEC3PARAM),
                QType::OPENPGPKEY => {
                    self.r_data = get_rr!(buffer, OPENPGPKEY, RData::OPENPGPKEY, self.rd_length)
                }
                QType::OPT => {
                    let mut v: Vec<OptOption> = Vec::new();
                    let mut current_length = 0u16;

                    while current_length < self.rd_length {
                        let mut option = OptOption::default();
                        option.deserialize_from(buffer)?;
                        trace!("option={:?}", option);

                        current_length += option.length + 4;

                        v.push(option);
                    }

                    self.r_data = RData::OPT(v)
                }
                QType::PTR => self.r_data = get_rr!(buffer, PTR, RData::PTR),
                QType::RP => self.r_data = get_rr!(buffer, RP, RData::RP),
                QType::RRSIG => self.r_data = get_rr!(buffer, RRSIG, RData::RRSIG, self.rd_length),
                QType::SMIMEA => {
                    self.r_data = get_rr!(buffer, SMIMEA, RData::SMIMEA, self.rd_length)
                }
                QType::SRV => self.r_data = get_rr!(buffer, SRV, RData::SRV),
                QType::SOA => self.r_data = get_rr!(buffer, SOA, RData::SOA),
                QType::SSHFP => self.r_data = get_rr!(buffer, SSHFP, RData::SSHFP, self.rd_length),
                QType::SVCB => self.r_data = get_rr!(buffer, SVCB, RData::SVCB, self.rd_length),
                QType::TLSA => self.r_data = get_rr!(buffer, TLSA, RData::TLSA, self.rd_length),
                QType::TXT => self.r_data = get_rr!(buffer, TXT, RData::TXT),
                QType::URI => self.r_data = get_rr!(buffer, URI, RData::URI, self.rd_length),
                QType::ZONEMD => {
                    self.r_data = get_rr!(buffer, ZONEMD, RData::ZONEMD, self.rd_length)
                }
                _ => {
                    // allocate the buffer to hold the data
                    let mut buf = Buffer::with_capacity(self.rd_length);
                    buf.deserialize_from(buffer)?;
                    self.r_data = RData::UNKNOWN(buf);
                }
            }
        }
        // a specific processing when OPT record has no options (rd_length == 0)
        // because by default RData enum is UNKNOWN
        else if self.r#type == QType::OPT {
            self.r_data = RData::OPT(Vec::new());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use crate::dns::rfc::a::A;
    use crate::dns::rfc::{
        aaaa::AAAA,
        domain::DomainName,
        qclass::QClass,
        qtype::QType,
        rdata::RData,
        resource_record::{OptOrClassTtl, RegularClassTtl},
    };

    use type2network::FromNetworkOrder;

    use super::ResourceRecord;

    #[test]
    fn a_record() {
        let data = b"\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x00\x00\x00\xbe\x00\x04\x8e\xfa\xb3\x44";
        let mut buffer = std::io::Cursor::new(&data[..]);

        let mut rr = ResourceRecord::default();
        rr.deserialize_from(&mut buffer).unwrap();

        let ip = rr.ip_address().unwrap();
        assert_eq!(ip, Ipv4Addr::from_str("142.250.179.68").unwrap());

        assert_eq!(rr.name, DomainName::try_from("www.google.com.").unwrap());
        assert_eq!(rr.r#type, QType::A);
        assert!(
            matches!(rr.opt_or_class_ttl, OptOrClassTtl::Regular(x) if x == RegularClassTtl{ class: QClass::IN, ttl: 190 })
        );
        assert_eq!(rr.rd_length, 4);
        assert!(
            matches!(rr.r_data, RData::A(a) if a == A(Ipv4Addr::from_str("142.250.179.68").unwrap()))
        );
    }

    #[test]
    fn aaaa_record() {
        let data = b"\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x1c\x00\x01\x00\x00\x00\xfd\x00\x10\x2a\x00\x14\x50\x40\x07\x08\x18\x00\x00\x00\x00\x00\x00\x20\x04";
        let mut buffer = std::io::Cursor::new(&data[..]);

        let mut rr = ResourceRecord::default();
        rr.deserialize_from(&mut buffer).unwrap();

        let ip = rr.ip_address().unwrap();

        assert_eq!(ip, Ipv6Addr::from_str("2a00:1450:4007:818::2004").unwrap());

        assert_eq!(rr.name, DomainName::try_from("www.google.com.").unwrap());
        assert_eq!(rr.r#type, QType::AAAA);
        assert!(
            matches!(rr.opt_or_class_ttl, OptOrClassTtl::Regular(x) if x == RegularClassTtl{ class: QClass::IN, ttl: 253 })
        );
        assert_eq!(rr.rd_length, 16);
        assert!(
            matches!(rr.r_data, RData::AAAA(aaaa) if aaaa == AAAA(Ipv6Addr::from_str("2a00:1450:4007:818::2004").unwrap()))
        );
    }

    #[test]
    fn soa_record() {
        let data = b"\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x06\x00\x01\x00\x00\x00\x17\x00\x26\x03\x6e\x73\x31\xc0\x10\x09\x64\x6e\x73\x2d\x61\x64\x6d\x69\x6e\xc0\x10\x27\x12\x10\xb8\x00\x00\x03\x84\x00\x00\x03\x84\x00\x00\x07\x08\x00\x00\x00\x3c";
        let mut buffer = std::io::Cursor::new(&data[..]);

        let mut rr = ResourceRecord::default();
        rr.deserialize_from(&mut buffer).unwrap();

        assert_eq!(rr.name, DomainName::try_from("www.google.com.").unwrap());
        assert_eq!(rr.r#type, QType::SOA);
        assert!(
            matches!(rr.opt_or_class_ttl, OptOrClassTtl::Regular(x) if x == RegularClassTtl{ class: QClass::IN, ttl: 23 })
        );
        assert_eq!(rr.rd_length, 38);
        if let RData::SOA(soa) = rr.r_data {
            assert_eq!(soa.rname, DomainName::try_from("dns-admin.").unwrap());
            assert_eq!(soa.serial, 655495352);
            assert_eq!(soa.refresh, 900);
            assert_eq!(soa.retry, 900);
            assert_eq!(soa.expire, 1800);
            assert_eq!(soa.minimum, 60);
        }
    }
}
