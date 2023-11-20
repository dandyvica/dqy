use std::{
    fmt,
    io::{Cursor, Error, ErrorKind},
};

use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use super::{
    a::A, aaaa::AAAA, char_string::CharacterString, cname::CNAME, domain::DomainName, hinfo::HINFO,
    loc::LOC, mx::MX, ns::NS, qclass::QClass, qtype::QType, soa::SOA, txt::TXT,
};

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

#[derive(Debug, ToNetwork)]
pub enum Class {
    Qc(QClass),
    Payload(u16), // case of OPT
}

impl<'a> Default for Class {
    fn default() -> Self {
        Class::Qc(QClass::IN)
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Class::Qc(cl) => write!(f, "{}", cl),
            Class::Payload(pl) => write!(f, "{}", pl),
        }
    }
}

#[derive(Debug, Default, ToNetwork, FromNetwork)]
pub struct ExtendedRcode {
    pub extented_rcode: u8,
    pub version: u8,
    pub doz: u16,
}

#[derive(Debug, ToNetwork)]
pub enum Ttl {
    Ttl(u32),
    Ext(ExtendedRcode), // case of OPT
}

impl<'a> Default for Ttl {
    fn default() -> Self {
        Ttl::Ttl(0)
    }
}

impl fmt::Display for Ttl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ttl::Ttl(ttl) => write!(f, "{}", ttl),
            Ttl::Ext(ecode) => write!(
                f,
                "extented_rcode: {} version: {} dos: {}",
                ecode.extented_rcode, ecode.version, ecode.doz
            ),
        }
    }
}

#[derive(Debug, Default, ToNetwork)]
pub struct ResourceRecord<'a> {
    pub name: DomainName<'a>, // an owner name, i.e., the name of the node to which this resource record pertains.
    pub r#type: QType,        // two octets containing one of the RR TYPE codes.
    pub class: Class, // two octets containing one of the RR CLASS codes or payload size in case of OPT
    pub ttl: Ttl, //   a bit = 32 signed (actually unsigned) integer that specifies the time interval
    // that the resource record may be cached before the source
    // of the information should again be consulted. Zero
    // values are interpreted to mean that the RR can only be
    // used for the transaction in progress, and should not be
    // cached.  For example, SOA records are always distributed
    // with a zero TTL to prohibit caching.  Zero values can
    // also be used for extremely volatile data.
    pub rd_length: u16, // an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
    pub r_data: Option<RData<'a>>,
    //  a variable length string of octets that describes the
    //  resource.  The format of this information varies
    //  according to the TYPE and CLASS of the resource record.
}

macro_rules! rr_display {
    ($fmt:expr, $rd_data:expr, $rd_arm:path, $tag:literal) => {
        match $rd_data {
            Some($rd_arm(x)) => write!($fmt, "{}", x),
            _ => panic!("unexpected error when displaying RR {}", $tag),
        }
    };
}

impl<'a> fmt::Display for ResourceRecord<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<10} {:<10?} {:<10} {:<10} {:<10}",
            self.name,
            self.r#type,
            self.class,
            self.ttl,
            self.rd_length
        )?;

        match self.r#type {
            QType::A => rr_display!(f, &self.r_data, RData::A, "A"),
            QType::AAAA => rr_display!(f, &self.r_data, RData::AAAA, "AAAA"),
            QType::CNAME => rr_display!(f, &self.r_data, RData::CName, "CNAME"),
            QType::HINFO => rr_display!(f, &self.r_data, RData::HInfo, "HINFO"),
            QType::NS => rr_display!(f, &self.r_data, RData::Ns, "NS"),
            QType::TXT => rr_display!(f, &self.r_data, RData::Txt, "TXT"),
            QType::SOA => rr_display!(f, &self.r_data, RData::Soa, "SOA"),
            QType::MX => rr_display!(f, &self.r_data, RData::Mx, "MX"),
            _ => unimplemented!(),
        }
    }
}

// Macro used to ease the ResourceRecord implementation of the FromNetworkOrder trait
macro_rules! get_rr {
    ($buffer:ident, $t:ty, $arm:path) => {{
        let mut x = <$t>::default();
        x.deserialize_from($buffer)?;
        Some($arm(x))
    }};
}

// a helper function to deserialize any type
fn deserialize_from<'a, T: Default + FromNetworkOrder<'a>>(
    buffer: &mut Cursor<&'a [u8]>,
) -> std::io::Result<T> {
    let mut value = T::default();
    value.deserialize_from(buffer)?;

    Ok(value)
}

impl<'a> FromNetworkOrder<'a> for ResourceRecord<'a> {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        self.name.deserialize_from(buffer)?;
        self.r#type.deserialize_from(buffer)?;

        // match wheter it's an OPT or not
        if self.r#type == QType::OPT {
            // class is payload size in case of OPT
            let pl: u16 = deserialize_from(buffer)?;
            self.class = Class::Payload(pl);

            // ttl is an extended rcode in case of OPT
            let ext: ExtendedRcode = deserialize_from(buffer)?;
            self.ttl = Ttl::Ext(ext);
        } else {
            // class is QClass in case of RR
            let qc: u16 = deserialize_from(buffer)?;
            let qclass = QClass::try_from(qc as u64).map_err(|e| {
                let msg = format!("unknown Qclass {}", e);
                Error::new(ErrorKind::Other, msg.to_owned())
            })?;
            self.class = Class::Qc(qclass);

            // ttl is real ttl in case of RR
            let ttl: u32 = deserialize_from(buffer)?;
            self.ttl = Ttl::Ttl(ttl);
        }

        self.rd_length.deserialize_from(buffer)?;

        if self.rd_length != 0 {
            match self.r#type {
                QType::A => self.r_data = get_rr!(buffer, A, RData::A),
                QType::AAAA => self.r_data = get_rr!(buffer, AAAA, RData::AAAA),
                QType::CNAME => self.r_data = get_rr!(buffer, CNAME, RData::CName),
                QType::HINFO => self.r_data = get_rr!(buffer, HINFO, RData::HInfo),
                QType::NS => self.r_data = get_rr!(buffer, NS, RData::Ns),
                QType::TXT => self.r_data = get_rr!(buffer, TXT, RData::Txt),
                QType::SOA => self.r_data = get_rr!(buffer, SOA, RData::Soa),
                //QType::OPT => self.r_data = get_rr!(buffer, OPTData, RData::Opt),
                // QType::DNSKEY => {
                //     let mut x = DNSKEY::default();
                //     x.key = Vec::with_capacity((self.rd_length - 4) as usize);

                //     x.deserialize_from(buffer)?;
                //     self.r_data = Some(RData::DnsKey(x))
                // }
                QType::MX => self.r_data = get_rr!(buffer, MX, RData::Mx),
                QType::LOC => self.r_data = get_rr!(buffer, LOC, RData::Loc),
                _ => unimplemented!("the {:?} RR is not yet implemented", self.r#type),
            }
            //self.r_data = Some(Vec::with_capacity(self.rd_length as usize));
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum RData<'a> {
    A(A),
    AAAA(AAAA),
    CName(CNAME<'a>),
    HInfo(HINFO<'a>),
    //Opt(OPTData),
    Soa(SOA<'a>),
    Ns(NS<'a>),
    Txt(TXT<'a>),
    Mx(MX<'a>),
    Loc(LOC), //DnsKey(DNSKEY),
}

impl<'a> Default for RData<'a> {
    fn default() -> Self {
        Self::A(A(0))
    }
}

impl<'a> ToNetworkOrder for RData<'a> {
    fn serialize_to(&self, _buffer: &mut Vec<u8>) -> std::io::Result<usize> {
        // let mut length = 0usize;

        // match self {
        //     RData::Opt(opt_data) => {
        //         length += opt_data.to_network_order(buffer)?;
        //     }
        //     _ => unimplemented!("For Rdata, only OPT is implemented for ToNetworkOrder"),
        // }

        // Ok(length)
        Ok(0)
    }
}

