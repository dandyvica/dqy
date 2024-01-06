use std::{fmt, io::Cursor};

use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::ToNetwork;

use super::{
    a::A, aaaa::AAAA, cname::CNAME, dnskey::DNSKEY, domain::DomainName, hinfo::HINFO, loc::LOC,
    mx::MX, ns::NS, opt::opt::OptTTL, ptr::PTR, qclass::QClass, qtype::QType, rdata::RData,
    soa::SOA, txt::TXT,
};

use crate::{
    databuf::Buffer,
    either_or::EitherOr,
    rfc::{
        afsdb::AFSDB,
        apl::APL,
        caa::CAA,
        cert::CERT,
        csync::CSYNC,
        dhcid::DHCID,
        dname::DNAME,
        dnskey::CDNSKEY,
        ds::{CDS, DLV, DS},
        eui48::EUI48,
        eui64::EUI64,
        hip::HIP,
        kx::KX,
        naptr::NAPTR,
        nsec::NSEC,
        nsec3::NSEC3,
        nsec3param::NSEC3PARAM,
        openpgpkey::OPENPGPKEY,
        opt::opt::OptOption,
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
pub(super) type RR<'a> = ResourceRecord<'a, RData<'a>>;

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

        debug!(
            "found RR: type:{:?} name:<{}> ttl:{} RD_length:{}",
            self.r#type, self.name, self.ttl, self.rd_length
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

        Ok(())
    }
}
