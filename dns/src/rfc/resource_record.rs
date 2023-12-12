use std::{fmt, io::Cursor};

use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::ToNetwork;

use super::{
    a::A, aaaa::AAAA, cname::CNAME, dnskey::DNSKEY, domain::DomainName, hinfo::HINFO, loc::LOC,
    mx::MX, ns::NS, opt::opt::OptTTL, ptr::PTR, qclass::QClass, qtype::QType, rdata::RData,
    soa::SOA, txt::TXT,
};

use crate::{
    buffer::Buffer,
    either_or::EitherOr,
    rfc::{
        ds::DS,
        nsec::NSEC,
        nsec3::{NSEC3, NSEC3PARAM},
        opt::opt::OptOption,
        rrsig::RRSIG,
    },
};

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
    pub class: EitherOr<QClass, u16>, // two octets containing one of the RR CLASS codes or payload size in case of OPT
    pub ttl: EitherOr<u32, OptTTL>, //   a bit = 32 signed (actually unsigned) integer that specifies the time interval
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

impl<'a> fmt::Display for RR<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<28} {:<10} {:<10} {:<10} {:<10}",
            self.name.to_string(),
            self.r#type.to_string(),
            self.class.to_string(),
            self.ttl.to_string(),
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

impl<'a> FromNetworkOrder<'a> for RR<'a> {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        self.name.deserialize_from(buffer)?;
        self.r#type.deserialize_from(buffer)?;

        // class is either a Qclass or in case of OPT the payload value
        self.class = {
            let mut cl = 0u16;
            cl.deserialize_from(buffer)?;

            match self.r#type {
                QType::OPT => EitherOr::new_right(cl),
                _ => {
                    let qc = QClass::try_from(cl).unwrap();
                    EitherOr::new_left(qc)
                }
            }
        };

        // TTL is the same
        self.ttl = if self.r#type == QType::OPT {
            let mut ext = OptTTL::default();
            ext.deserialize_from(buffer)?;
            EitherOr::new_right(ext)
        } else {
            let mut ttl = 0u32;
            ttl.deserialize_from(buffer)?;
            EitherOr::new_left(ttl)
        };

        // self.ttl.deserialize_from(buffer)?;
        self.rd_length.deserialize_from(buffer)?;

        trace!(
            "found RR: name:<{}> type:{:?} ttl:{} RD_length:{}",
            self.name,
            self.r#type,
            self.ttl,
            self.rd_length
        );

        if self.rd_length != 0 {
            match self.r#type {
                QType::A => self.r_data = get_rr!(buffer, A, RData::A),
                QType::AAAA => self.r_data = get_rr!(buffer, AAAA, RData::AAAA),
                QType::CNAME => self.r_data = get_rr!(buffer, CNAME, RData::CNAME),
                QType::HINFO => self.r_data = get_rr!(buffer, HINFO, RData::HINFO),
                QType::PTR => self.r_data = get_rr!(buffer, PTR, RData::PTR),
                QType::NS => self.r_data = get_rr!(buffer, NS, RData::NS),
                QType::TXT => self.r_data = get_rr!(buffer, TXT, RData::TXT),
                QType::SOA => self.r_data = get_rr!(buffer, SOA, RData::SOA),
                QType::OPT => {
                    let mut v: Vec<OptOption> = Vec::new();
                    let mut current_length = 0u16;

                    while current_length < self.rd_length {
                        let mut option = OptOption::default();
                        option.deserialize_from(buffer)?;
                        println!("option={:?}", option);

                        current_length += option.length + 4;

                        v.push(option);
                    }

                    self.r_data = RData::OPT(v)
                }
                QType::DNSKEY => {
                    self.r_data = get_rr!(buffer, DNSKEY, RData::DNSKEY, self.rd_length - 4)
                }
                QType::DS => self.r_data = get_rr!(buffer, DS, RData::DS, self.rd_length - 4),
                QType::NSEC => self.r_data = get_rr!(buffer, NSEC, RData::NSEC, self.rd_length),
                QType::NSEC3 => self.r_data = get_rr!(buffer, NSEC3, RData::NSEC3, self.rd_length),

                // QType::DS => {
                //     let mut x = DS::new(self.rd_length - 4);

                //     x.deserialize_from(buffer)?;
                //     self.r_data = RData::DS(x)
                // }
                // QType::NSEC3 => {
                //     let mut x = NSEC3::default();
                //     x.rd_length = self.rd_length;

                //     x.deserialize_from(buffer)?;
                //     self.r_data = RData::NSEC3(x)
                // }
                QType::NSEC3PARAM => self.r_data = get_rr!(buffer, NSEC3PARAM, RData::NSEC3PARAM),
                QType::RRSIG => {
                    let mut x = RRSIG::default();

                    // name & signature are not yet to be deserialized
                    x.deserialize_from(buffer)?;

                    // we need this trick to not deserialize the name because its length is unknown yet
                    // we need the length to allocate the Buffer for the signature
                    x.name.deserialize_from(buffer)?;
                    x.signature = Buffer::new(self.rd_length - 18 - x.name.len() as u16);
                    x.signature.deserialize_from(buffer)?;

                    self.r_data = RData::RRSIG(x)
                }
                QType::MX => self.r_data = get_rr!(buffer, MX, RData::MX),
                QType::LOC => self.r_data = get_rr!(buffer, LOC, RData::LOC),
                _ => {
                    // allocate the buffer to hold the data
                    let mut buf = Buffer::new(self.rd_length);
                    buf.deserialize_from(buffer)?;
                    self.r_data = RData::UNKNOWN(buf);
                }
            }
        }

        Ok(())
    }
}
