use std::fmt::{self};

use serde::Serialize;
use type2network::ToNetworkOrder;

use crate::buffer::Buffer;

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
    // dname::DNAME,
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
    opt::opt::OptOption,
    ptr::PTR,
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
    UNKNOWN(Buffer),
    URI(URI),
    ZONEMD(ZONEMD),
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
