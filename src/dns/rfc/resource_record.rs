use std::{fmt, io::Cursor, net::IpAddr};

use serde::Serialize;
use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use super::domain::ROOT_DOMAIN;
use super::opt::OptionDataValue;
use super::{domain::DomainName, qclass::QClass, qtype::QType, rdata::RData};
use crate::dns::rfc::opt::opt_rr::{OptOption, OptionList};

use log::{debug, trace};

macro_rules! getter {
    ($fname:ident, $type:ty) => {
        #[inline]
        pub fn $fname(&self) -> $type {
            self.$fname
        }
    };
}

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

// Manage case of regular RR and OPT
#[derive(Debug, Default, PartialEq, ToNetwork, FromNetwork)]
pub struct RegularClassTtl {
    pub(super) class: QClass,
    pub(super) ttl: u32,
}

impl RegularClassTtl {
    getter!(class, QClass);
    getter!(ttl, u32);
}

// Case of OPT RR
// https://www.rfc-editor.org/rfc/rfc6891#section-6.1.3
// +0 (MSB)                            +1 (LSB)
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 0: |         EXTENDED-RCODE        |            VERSION            |
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 2: | DO|                           Z                               |
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
#[derive(Debug, Default, PartialEq, ToNetwork, FromNetwork)]
pub struct OptPayload {
    payload: u16,
    extended_rcode: u8,
    version: u8,
    flags: u16,
}

impl OptPayload {
    getter!(payload, u16);
    getter!(extended_rcode, u8);
    getter!(version, u8);
    getter!(flags, u16);
}

// CLASS & TTL vary if RR is OPT or not
#[derive(ToNetwork, PartialEq)]
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
            OptOrClassTtl::Opt(x) => write!(f, "{} {} {} {}", x.payload, x.extended_rcode, x.version, x.flags),
        }
    }
}

impl fmt::Debug for OptOrClassTtl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptOrClassTtl::Regular(x) => write!(f, "{:<10} {:<10}", x.class.to_string(), x.ttl),
            OptOrClassTtl::Opt(x) => write!(f, "{} {} {} {}", x.payload, x.extended_rcode, x.version, x.flags),
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
pub struct Ttl(u32);

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

impl From<u32> for Ttl {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

#[derive(Default, ToNetwork, Serialize)]
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
    rd_length: u16, // an unsigned 16 bit integer that specifies the length in octets of the RDATA field.

    #[serde(flatten)]
    pub r_data: RData,
    //  a variable length string of octets that describes the
    //  resource.  The format of this information varies
    //  according to the TYPE and CLASS of the resource record.
}

// don't use Show trait to provide extra length used to align output
// use this function
impl ResourceRecord {
    #[inline]
    pub fn rd_length(&self) -> u16 {
        self.rd_length
    }

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

//─────────────────────────────────────opt_or_class_ttl──────────────────────────────────────────────
// OPT is a special case of RR
//───────────────────────────────────────────────────────────────────────────────────────────────────
pub type OPT = ResourceRecord;

impl OPT {
    // OPT is a special case of RR
    pub fn new(bufsize: u16, flags: Option<u16>) -> Self {
        let opt_payload = OptPayload {
            payload: bufsize,
            flags: flags.unwrap_or_default(),
            ..Default::default()
        };

        // OPT qname is root
        Self {
            name: ROOT_DOMAIN,
            r#type: QType::OPT,
            opt_or_class_ttl: OptOrClassTtl::Opt(opt_payload),
            rd_length: 0,
            r_data: RData::OPT(OptionList::default()), // no options added yet
        }
    }

    // add another option in OPT record? Only valid for queries
    pub fn add_option<T: OptionDataValue>(&mut self, data: T) {
        // build the option structure
        let option = OptOption {
            code: data.code(),
            length: data.len(),
            data: data.data(),
        };

        trace!("OPTION:{:?}", option);

        // add in the list of options
        self.rd_length += 4 + option.length;
        if let RData::OPT(opt) = &mut self.r_data {
            opt.push(option);
        }
    }
}

impl fmt::Debug for OPT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {:?}", self.name, self.r#type, self.opt_or_class_ttl)?;
        Ok(())
    }
}

impl fmt::Display for ResourceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<28} {:<10} {} {:<10}",
            self.name.to_string(),
            self.r#type.to_string(),
            self.opt_or_class_ttl,
            self.rd_length
        )?;

        if self.rd_length != 0 {
            write!(f, "{}", self.r_data)?;
        }

        Ok(())
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
            self.r_data = RData::from_bytes(&self.r#type, self.rd_length, buffer)?;
        }
        // a specific processing when OPT record has no options (rd_length == 0)
        // because by default RData enum is UNKNOWN
        else if self.r#type == QType::OPT {
            self.r_data = RData::OPT(OptionList::default());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use crate::dns::rfc::a::A;
    use crate::dns::rfc::resource_record::Ttl;
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
    fn rax_ttl() {
        let ttl = Ttl(1);
        assert_eq!(ttl.to_string(), "1s");

        let ttl = Ttl(710);
        assert_eq!(ttl.to_string(), "11m50s");

        let ttl = Ttl(1163);
        assert_eq!(ttl.to_string(), "19m23s");

        let ttl = Ttl(86400);
        assert_eq!(ttl.to_string(), "1d0h0m0s");

        let ttl = Ttl(86401);
        assert_eq!(ttl.to_string(), "1d0h0m1s");

        let ttl = Ttl(86461);
        assert_eq!(ttl.to_string(), "1d0h1m1s");
    }

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
        assert!(matches!(rr.r_data, RData::A(a) if a == A(Ipv4Addr::from_str("142.250.179.68").unwrap())));
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
