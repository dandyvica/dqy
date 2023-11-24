use std::{fmt, io::Cursor};

use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::ToNetwork;

use super::{
    a::A,
    aaaa::AAAA,
    cname::CNAME,
    dnskey::DNSKEY,
    domain::DomainName,
    hinfo::HINFO,
    loc::LOC,
    mx::MX,
    ns::NS,
    ptr::PTR,
    qclass::{Class, QClass},
    qtype::QType,
    rdata::RData,
    soa::SOA,
    txt::TXT,
};

use crate::{rfc6891::opt::*, rfc1035::{ds::DS, rrsig::RRSIG}};

use log::trace;

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

#[derive(Debug, Default, ToNetwork)]
pub struct ResourceRecord<'a, T>
where
    T: ToNetworkOrder,
{
    pub name: DomainName<'a>, // an owner name, i.e., the name of the node to which this resource record pertains.
    pub r#type: QType,        // two octets containing one of the RR TYPE codes.
    pub class: Class, // two octets containing one of the RR CLASS codes or payload size in case of OPT
    pub ttl: u32, //   a bit = 32 signed (actually unsigned) integer that specifies the time interval
    // that the resource record may be cached before the source
    // of the information should again be consulted. Zero
    // values are interpreted to mean that the RR can only be
    // used for the transaction in progress, and should not be
    // cached.  For example, SOA records are always distributed
    // with a zero TTL to prohibit caching.  Zero values can
    // also be used for extremely volatile data.
    pub rd_length: u16, // an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
    pub r_data: T,
    //  a variable length string of octets that describes the
    //  resource.  The format of this information varies
    //  according to the TYPE and CLASS of the resource record.
}

// define RRs used in query and response
pub type MetaRR<'a> = ResourceRecord<'a, Vec<u8>>;
pub type RR<'a> = ResourceRecord<'a, RData<'a>>;

impl<'a> ResourceRecord<'a, Vec<u8>> {
    pub fn new_opt(bufsize: Option<u16>) -> Self {
        let mut opt = MetaRR::default();
        opt.r#type = QType::OPT;
        opt.class = Class::Payload(bufsize.unwrap_or(1232));

        opt
    }

    pub fn set_edns_nsid(&mut self) -> std::io::Result<usize> {
        let mut opt = OPT::default();
        opt.code = OptionCode::NSID as u16;

        opt.serialize_to(&mut self.r_data)
    }
}

impl<'a> fmt::Display for RR<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<28} {:<10} {:<10} {:<10} {:<10}",
            self.name.to_string(),
            self.r#type.to_string(),
            self.class.to_string(),
            self.ttl,
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
    ($buffer:ident, $t:ty, $arm:path) => {{
        let mut x = <$t>::default();
        x.deserialize_from($buffer)?;
        $arm(x)
    }};
}

impl<'a> FromNetworkOrder<'a> for RR<'a> {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        self.name.deserialize_from(buffer)?;
        self.r#type.deserialize_from(buffer)?;

        let mut cl = 0u16;
        cl.deserialize_from(buffer)?;

        self.class = match self.r#type {
            QType::OPT => Class::Payload(cl),
            _ => {
                let qc = QClass::try_from(cl as u64).unwrap();
                Class::Qclass(qc)
            }
        };

        self.ttl.deserialize_from(buffer)?;
        self.rd_length.deserialize_from(buffer)?;

        trace!("RR type: {:?}", self.r#type);

        if self.rd_length != 0 {
            match self.r#type {
                QType::A => self.r_data = get_rr!(buffer, A, RData::A),
                QType::AAAA => self.r_data = get_rr!(buffer, AAAA, RData::AAAA),
                QType::CNAME => self.r_data = get_rr!(buffer, CNAME, RData::CName),
                QType::HINFO => self.r_data = get_rr!(buffer, HINFO, RData::HInfo),
                QType::PTR => self.r_data = get_rr!(buffer, PTR, RData::Ptr),
                QType::NS => self.r_data = get_rr!(buffer, NS, RData::Ns),
                QType::TXT => self.r_data = get_rr!(buffer, TXT, RData::Txt),
                QType::SOA => self.r_data = get_rr!(buffer, SOA, RData::Soa),
                QType::OPT => {
                    println!("found OPT");
                    let mut v: Vec<OPT> = Vec::new();
                    let mut current_length = 0u16;

                    while current_length <= self.rd_length {
                        let mut opt = OPT::default();
                        opt.deserialize_from(buffer)?;

                        current_length += opt.length;

                        v.push(opt);
                    }

                    self.r_data = RData::Opt(Some(v))
                }
                QType::DNSKEY => {
                    let mut x = DNSKEY::default();
                    x.key = Vec::with_capacity((self.rd_length - 4) as usize);

                    x.deserialize_from(buffer)?;
                    self.r_data = RData::DnsKey(x)
                }
                QType::DS => {
                    let mut x = DS::default();
                    x.digest = Vec::with_capacity((self.rd_length - 4) as usize);

                    x.deserialize_from(buffer)?;
                    self.r_data = RData::Ds(x)                    
                },
                QType::RRSIG => {
                    let mut x = RRSIG::default();
                    x.type_covered.deserialize_from(buffer)?;
                    x.algorithm.deserialize_from(buffer)?;
                    x.label.deserialize_from(buffer)?;
                    x.ttl.deserialize_from(buffer)?;
                    x.sign_expiration.deserialize_from(buffer)?;
                    x.sing_inception.deserialize_from(buffer)?;
                    x.key_tag.deserialize_from(buffer)?;
                    x.name.deserialize_from(buffer)?;
                    //x.signature = Vec::with_capacity((self.rd_length - 11 - ) as usize);
                    self.r_data = RData::Rrsig(x)                    
                },
                QType::MX => self.r_data = get_rr!(buffer, MX, RData::Mx),
                QType::LOC => self.r_data = get_rr!(buffer, LOC, RData::Loc),
                _ => unimplemented!("the {:?} RR is not yet implemented", self.r#type),
            }
            //self.r_data = Some(Vec::with_capacity(self.rd_length as usize));
        }

        Ok(())
    }
}

// fn deserialize_helper<T: Default>(length: u16) -> T {
//     let mut x: DNSKEY = T::default();
//     x.key = Vec::with_capacity((self.rd_length - 4) as usize);

//     x.deserialize_from(buffer)?;
//     self.r_data = RData::DnsKey(x)
// }
