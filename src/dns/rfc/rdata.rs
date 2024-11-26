use std::{
    fmt::{self},
    io::Cursor,
};

use colored::{ColoredString, Colorize};
use log::trace;
use serde::Serialize;
use type2network::ToNetworkOrder;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{dns::buffer::Buffer, show::ToColor};

use super::{
    a::A,
    aaaa::AAAA,
    afsdb::AFSDB,
    apl::APL,
    caa::CAA,
    cert::CERT,
    cname::{CNAME, DNAME},
    csync::CSYNC,
    dhcid::DHCID,
    dnskey::{CDNSKEY, DNSKEY},
    ds::{CDS, DLV, DS},
    eui48::EUI48,
    eui64::EUI64,
    hinfo::HINFO,
    hip::HIP,
    ipseckey::IPSECKEY,
    kx::KX,
    loc::LOC,
    mx::MX,
    naptr::NAPTR,
    ns::NS,
    nsec::NSEC,
    nsec3::NSEC3,
    nsec3param::NSEC3PARAM,
    openpgpkey::OPENPGPKEY,
    opt::opt_rr::OptOption,
    ptr::PTR,
    qtype::QType,
    rp::RP,
    rrsig::RRSIG,
    soa::SOA,
    srv::SRV,
    sshfp::SSHFP,
    svcb::{HTTPS, SVCB},
    tlsa::{SMIMEA, TLSA},
    txt::TXT,
    uri::URI,
    zonemd::ZONEMD,
};

#[derive(Debug, Serialize)]
struct OptionList(Vec<OptOption>);

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Serialize)]
#[serde(tag = "type", content = "rdata")]
pub(super) enum RData {
    // RData definitions
    A(A),
    AAAA(AAAA),
    AFSDB(AFSDB),
    APL(APL),
    CAA(CAA),
    CDNSKEY(CDNSKEY),
    CDS(CDS),
    CERT(CERT),
    CNAME(CNAME),
    CSYNC(CSYNC),
    DHCID(DHCID),
    DLV(DLV),
    DNAME(DNAME),
    DNSKEY(DNSKEY),
    DS(DS),
    EUI48(EUI48),
    EUI64(EUI64),
    HINFO(HINFO),
    HIP(HIP),
    HTTPS(HTTPS),
    IPSECKEY(IPSECKEY),
    KX(KX),
    LOC(LOC),
    MX(MX),
    NAPTR(NAPTR),
    NS(NS),
    NSEC(NSEC),
    NSEC3(NSEC3),
    NSEC3PARAM(NSEC3PARAM),
    OPENPGPKEY(OPENPGPKEY),
    OPT(Vec<OptOption>),
    PTR(PTR),
    RP(RP),
    RRSIG(RRSIG),
    SMIMEA(SMIMEA),
    SOA(SOA),
    SRV(SRV),
    SSHFP(SSHFP),
    SVCB(SVCB),
    TLSA(TLSA),
    TXT(TXT),
    // when the RDATA is not recognized
    UNKNOWN(Buffer),
    URI(URI),
    ZONEMD(ZONEMD),
}

// Macro used to ease the ResourceRecord implementation of the FromNetworkOrder trait
macro_rules! get_rr {
    // to deserialize "simple" structs (like A)
    ($buffer:ident, $t:ty, $arm:path) => {{
        let mut x = <$t>::default();
        x.deserialize_from($buffer)?;
        Ok($arm(x))
    }};

    // to deserialize "complex" structs (like DNSKEY)
    ($buffer:ident, $t:ty, $arm:path, $e:expr) => {{
        let mut x = <$t>::new($e);
        x.deserialize_from($buffer)?;
        Ok($arm(x))
    }};
}

impl RData {
    // according to QType, map buffer to RData
    pub fn from_bytes<'a>(qt: &QType, length: u16, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<Self> {
        match qt {
            // RData enum
            QType::A => get_rr!(buffer, A, RData::A),
            QType::AAAA => get_rr!(buffer, AAAA, RData::AAAA),
            QType::AFSDB => get_rr!(buffer, AFSDB, RData::AFSDB),
            QType::APL => get_rr!(buffer, APL, RData::APL, length),
            QType::CDNSKEY => get_rr!(buffer, CDNSKEY, RData::CDNSKEY, length),
            QType::CAA => get_rr!(buffer, CAA, RData::CAA, length),
            QType::CDS => get_rr!(buffer, CDS, RData::CDS, length),
            QType::CERT => get_rr!(buffer, CERT, RData::CERT, length),
            QType::CNAME => get_rr!(buffer, CNAME, RData::CNAME),
            QType::CSYNC => get_rr!(buffer, CSYNC, RData::CSYNC, length),
            QType::DHCID => get_rr!(buffer, DHCID, RData::DHCID, length),
            QType::DNAME => get_rr!(buffer, DNAME, RData::DNAME),
            QType::DLV => get_rr!(buffer, DLV, RData::DLV, length),
            QType::DNSKEY => get_rr!(buffer, DNSKEY, RData::DNSKEY, length),
            QType::DS => get_rr!(buffer, DS, RData::DS, length),
            QType::EUI48 => get_rr!(buffer, EUI48, RData::EUI48),
            QType::EUI64 => get_rr!(buffer, EUI64, RData::EUI64),
            QType::HINFO => get_rr!(buffer, HINFO, RData::HINFO),
            QType::HIP => get_rr!(buffer, HIP, RData::HIP, length),
            QType::HTTPS => get_rr!(buffer, HTTPS, RData::HTTPS, length),
            QType::IPSECKEY => get_rr!(buffer, IPSECKEY, RData::IPSECKEY, length),
            QType::KX => get_rr!(buffer, KX, RData::KX),
            QType::LOC => get_rr!(buffer, LOC, RData::LOC),
            QType::MX => get_rr!(buffer, MX, RData::MX),
            QType::NAPTR => get_rr!(buffer, NAPTR, RData::NAPTR),
            QType::NS => get_rr!(buffer, NS, RData::NS),
            QType::NSEC => get_rr!(buffer, NSEC, RData::NSEC, length),
            QType::NSEC3 => get_rr!(buffer, NSEC3, RData::NSEC3, length),
            QType::NSEC3PARAM => get_rr!(buffer, NSEC3PARAM, RData::NSEC3PARAM),
            QType::OPENPGPKEY => get_rr!(buffer, OPENPGPKEY, RData::OPENPGPKEY, length),
            QType::OPT => {
                let mut v: Vec<OptOption> = Vec::new();
                let mut current_length = 0u16;

                while current_length < length {
                    let mut option = OptOption::default();
                    option.deserialize_from(buffer)?;
                    trace!("option={:?}", option);

                    current_length += option.length + 4;

                    v.push(option);
                }

                Ok(RData::OPT(v))
            }
            QType::PTR => get_rr!(buffer, PTR, RData::PTR),
            QType::RP => get_rr!(buffer, RP, RData::RP),
            QType::RRSIG => get_rr!(buffer, RRSIG, RData::RRSIG, length),
            QType::SMIMEA => get_rr!(buffer, SMIMEA, RData::SMIMEA, length),
            QType::SRV => get_rr!(buffer, SRV, RData::SRV),
            QType::SOA => get_rr!(buffer, SOA, RData::SOA),
            QType::SSHFP => get_rr!(buffer, SSHFP, RData::SSHFP, length),
            QType::SVCB => get_rr!(buffer, SVCB, RData::SVCB, length),
            QType::TLSA => get_rr!(buffer, TLSA, RData::TLSA, length),
            QType::TXT => get_rr!(buffer, TXT, RData::TXT),
            QType::URI => get_rr!(buffer, URI, RData::URI, length),
            QType::ZONEMD => get_rr!(buffer, ZONEMD, RData::ZONEMD, length),
            _ => {
                // allocate the buffer to hold the data
                let mut buf = Buffer::with_capacity(length);
                buf.deserialize_from(buffer)?;
                Ok(RData::UNKNOWN(buf))
            }
        }
    }
}

impl Default for RData {
    fn default() -> Self {
        Self::UNKNOWN(Buffer::default())
    }
}

impl ToNetworkOrder for RData {
    fn serialize_to(&self, _buffer: &mut Vec<u8>) -> std::io::Result<usize> {
        Ok(0)
    }
}

impl fmt::Display for RData {
    #[allow(unreachable_patterns)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // RData Display
            RData::A(a) => write!(f, "{}", a),
            RData::AAAA(a) => write!(f, "{}", a),
            RData::AFSDB(a) => write!(f, "{}", a),
            RData::APL(a) => write!(f, "{}", a),
            RData::CAA(a) => write!(f, "{}", a),
            RData::CDNSKEY(a) => write!(f, "{}", a),
            RData::CDS(a) => write!(f, "{}", a),
            RData::CERT(a) => write!(f, "{}", a),
            RData::CNAME(a) => write!(f, "{}", a),
            RData::CSYNC(a) => write!(f, "{}", a),
            RData::DHCID(a) => write!(f, "{}", a),
            RData::DLV(a) => write!(f, "{}", a),
            RData::DNAME(a) => write!(f, "{}", a),
            RData::DNSKEY(a) => write!(f, "{}", a),
            RData::DS(a) => write!(f, "{}", a),
            RData::EUI48(a) => write!(f, "{}", a),
            RData::EUI64(a) => write!(f, "{}", a),
            RData::HINFO(a) => write!(f, "{}", a),
            RData::HTTPS(a) => write!(f, "{}", a),
            RData::HIP(a) => write!(f, "{}", a),
            RData::IPSECKEY(a) => write!(f, "{}", a),
            RData::KX(a) => write!(f, "{}", a),
            RData::LOC(a) => write!(f, "{}", a),
            RData::MX(a) => write!(f, "{}", a),
            RData::NAPTR(a) => write!(f, "{}", a),
            RData::NS(a) => write!(f, "{}", a),
            RData::NSEC(a) => write!(f, "{}", a),
            RData::NSEC3(a) => write!(f, "{}", a),
            RData::NSEC3PARAM(a) => write!(f, "{}", a),
            RData::OPENPGPKEY(a) => write!(f, "{}", a),
            RData::OPT(a) => {
                for opt in a {
                    write!(f, "{}", opt)?;
                }
                Ok(())
            }
            RData::PTR(a) => write!(f, "{}", a),
            RData::RP(a) => write!(f, "{}", a),
            RData::RRSIG(a) => write!(f, "{}", a),
            RData::SOA(a) => write!(f, "{}", a),
            RData::SMIMEA(a) => write!(f, "{}", a),
            RData::SRV(a) => write!(f, "{}", a),
            RData::SSHFP(a) => write!(f, "{}", a),
            RData::SVCB(a) => write!(f, "{}", a),
            RData::TLSA(a) => write!(f, "{}", a),
            RData::TXT(a) => write!(f, "{}", a),
            RData::URI(a) => write!(f, "{}", a),
            RData::UNKNOWN(a) => write!(f, "RR NOT YET IMPLEMENTED: {}", a),
            RData::ZONEMD(a) => write!(f, "{}", a),
            _ => unimplemented!("not yet implemented"),
        }
    }
}

impl ToColor for RData {
    fn to_color(&self) -> ColoredString {
        self.to_string().bright_yellow()
    }
}
