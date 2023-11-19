use std::io::{Cursor, Error, ErrorKind};

use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use crate::{
    rfc1035::char_string::CharacterString, rfc1035::domain::DomainName, rfc1035::qclass::QClass,
    rfc1035::qtype::QType,
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
    Loc(LOC)
    //DnsKey(DNSKEY),
}

impl<'a> Default for RData<'a> {
    fn default() -> Self {
        Self::A(0)
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

//------------------------------------------------------------------------
// Definition of all RRs from all different RFCs starting with RFC1035
//------------------------------------------------------------------------

// A RR
pub type A = u32;

// HINFO RR
#[derive(Debug, Default, FromNetwork)]
pub struct HINFO<'a> {
    pub cpu: CharacterString<'a>,
    pub os: CharacterString<'a>,
}

// CNAME RR
pub type CNAME<'a> = DomainName<'a>;

// NS RR
pub type NS<'a> = DomainName<'a>;

// AAAA RR
pub type AAAA = [u8; 16];

// SOA RR
#[derive(Debug, Default, FromNetwork)]
pub struct SOA<'a> {
    pub mname: DomainName<'a>, // The <domain-name> of the name server that was the
    // original or primary source of data for this zone.
    pub rname: DomainName<'a>, // A <domain-name> which specifies the mailbox of the
    // person responsible for this zone.
    pub serial: u32, // The unsigned 32 bit version number of the original copy
    // of the zone.  Zone transfers preserve this value.  This
    // value wraps and should be compared using sequence space
    // arithmetic.
    pub refresh: u32, // A 32 bit time interval before the zone should be
    // refreshed.
    pub retry: u32, // A 32 bit time interval that should elapse before a
    // failed refresh should be retried.
    pub expire: u32, // A 32 bit time value that specifies the upper limit on
    // the time interval that can elapse before the zone is no
    // longer authoritative.
    pub minimum: u32, //The unsigned 32 bit minimum TTL field that should be
                      //exported with any RR from this zone.
}

// PTR RR
pub type PTR<'a> = DomainName<'a>;

// MX RR
#[derive(Debug, Default, FromNetwork)]
pub struct MX<'a> {
    pub preference: u16, // A 16 bit integer which specifies the preference given to
    // this RR among others at the same owner.  Lower values
    // are preferred.
    pub exchange: DomainName<'a>, // A <domain-name> which specifies a host willing to act as a mail exchange for the owner name.
}

// TXT RR
pub type TXT<'a> = CharacterString<'a>;

// RDATA RR
pub type RDATA = u32;

// LOC record (https://datatracker.ietf.org/doc/html/rfc1876)
#[derive(Debug, Default, FromNetwork)]
pub struct LOC {
    pub version: u8,
    pub size: u8,
    pub horiz_pre: u8,
    pub vert_pre: u8,
    pub latitude1: u16,
    pub latitude2: u16,
    pub longitude1: u16,
    pub longitude2: u16,
    pub altitude1: u16,
    pub altitude2: u16,
}
