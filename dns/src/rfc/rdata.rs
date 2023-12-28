use std::fmt::{self};

use type2network::ToNetworkOrder;

use super::{
    a::A, aaaa::AAAA, afsdb::AFSDB, apl::APL, caa::CAA, cert::CERT, cname::CNAME, csync::CSYNC,
    dnskey::DNSKEY, ds::DS, eui48::EUI48, eui64::EUI64, hinfo::HINFO, kx::KX, loc::LOC, mx::MX,
    naptr::NAPTR, ns::NS, nsec::NSEC, nsec3::NSEC3, nsec3param::NSEC3PARAM, openpgpkey::OPENPGPKEY,
    opt::opt::OptOption, ptr::PTR, rp::RP, rrsig::RRSIG, soa::SOA, tlsa::TLSA, txt::TXT, uri::URI,
    zonemd::ZONEMD,
};

use crate::buffer::Buffer;

#[derive(Debug)]
pub(super) enum RData<'a> {
    // RData definition
    A(A),
    AAAA(AAAA),
    AFSDB(AFSDB<'a>),
    APL(APL),
    CAA(CAA),
    CERT(CERT),
    CNAME(CNAME<'a>),
    CSYNC(CSYNC),
    DNSKEY(DNSKEY),
    DS(DS),
    EUI48(EUI48),
    EUI64(EUI64),
    HINFO(HINFO<'a>),
    KX(KX<'a>),
    LOC(LOC),
    MX(MX<'a>),
    NAPTR(NAPTR<'a>),
    NS(NS<'a>),
    NSEC(NSEC<'a>),
    NSEC3(NSEC3),
    NSEC3PARAM(NSEC3PARAM),
    OPENPGPKEY(OPENPGPKEY),
    OPT(Vec<OptOption>),
    PTR(PTR<'a>),
    RP(RP<'a>),
    RRSIG(RRSIG<'a>),
    SOA(SOA<'a>),
    TLSA(TLSA),
    TXT(TXT<'a>),
    UNKNOWN(Buffer),
    URI(URI),
    ZONEMD(ZONEMD),
}

impl<'a> Default for RData<'a> {
    fn default() -> Self {
        Self::A(A(0))
    }
}

impl<'a> ToNetworkOrder for RData<'a> {
    fn serialize_to(&self, _buffer: &mut Vec<u8>) -> std::io::Result<usize> {
        Ok(0)
    }
}

impl<'a> fmt::Display for RData<'a> {
    #[allow(unreachable_patterns)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // RData Display
            RData::A(a) => write!(f, "{}", a),
            RData::AAAA(a) => write!(f, "{}", a),
            RData::AFSDB(a) => write!(f, "{}", a),
            RData::APL(a) => write!(f, "{}", a),
            RData::CAA(a) => write!(f, "{}", a),
            RData::CERT(a) => write!(f, "{}", a),
            RData::CNAME(a) => write!(f, "{}", a),
            RData::CSYNC(a) => write!(f, "{}", a),
            RData::DNSKEY(a) => write!(f, "{}", a),
            RData::DS(a) => write!(f, "{}", a),
            RData::EUI48(a) => write!(f, "{}", a),
            RData::EUI64(a) => write!(f, "{}", a),
            RData::HINFO(a) => write!(f, "{}", a),
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
            RData::TLSA(a) => write!(f, "{}", a),
            RData::TXT(a) => write!(f, "{}", a),
            RData::URI(a) => write!(f, "{}", a),
            RData::UNKNOWN(a) => write!(f, "RR NOT YET IMPLEMENTED: {}", a),
            RData::ZONEMD(a) => write!(f, "{}", a),
            _ => unimplemented!("not yet implemented"),
        }
    }
}
