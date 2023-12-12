use std::fmt::{self};

use type2network::ToNetworkOrder;

use super::{
    a::A,
    aaaa::AAAA,
    cname::CNAME,
    dnskey::DNSKEY,
    ds::DS,
    hinfo::HINFO,
    loc::LOC,
    mx::MX,
    ns::NS,
    nsec::NSEC,
    nsec3::{NSEC3, NSEC3PARAM},
    opt::opt::OptOption,
    ptr::PTR,
    rrsig::RRSIG,
    soa::SOA,
    txt::TXT,
};

use crate::buffer::Buffer;

#[derive(Debug)]
pub enum RData<'a> {
    A(A),
    AAAA(AAAA),
    CNAME(CNAME<'a>),
    HINFO(HINFO<'a>),
    PTR(PTR<'a>),
    OPT(Vec<OptOption>),
    SOA(SOA<'a>),
    NS(NS<'a>),
    TXT(TXT<'a>),
    MX(MX<'a>),
    LOC(LOC),
    DNSKEY(DNSKEY),
    DS(DS),
    NSEC(NSEC<'a>),
    NSEC3(NSEC3),
    NSEC3PARAM(NSEC3PARAM),
    RRSIG(RRSIG<'a>),
    UNKNOWN(Buffer),
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RData::A(a) => write!(f, "{}", a),
            RData::AAAA(a) => write!(f, "{}", a),
            RData::CNAME(a) => write!(f, "{}", a),
            RData::HINFO(a) => write!(f, "{}", a),
            RData::PTR(a) => write!(f, "{}", a),
            RData::NS(a) => write!(f, "{}", a),
            RData::TXT(a) => write!(f, "{}", a),
            RData::SOA(a) => write!(f, "{}", a),
            RData::MX(a) => write!(f, "{}", a),
            RData::DNSKEY(a) => write!(f, "{}", a),
            RData::DS(a) => write!(f, "{}", a),
            RData::NSEC(a) => write!(f, "{}", a),
            RData::NSEC3(a) => write!(f, "{}", a),
            RData::NSEC3PARAM(a) => write!(f, "{}", a),
            RData::RRSIG(a) => write!(f, "{}", a),
            RData::OPT(a) => {
                for opt in a {
                    write!(f, "{}", opt)?;
                }
                Ok(())
            }
            RData::UNKNOWN(a) => write!(f, "NOT YET IMPLEMENTED: {}", a),
            _ => unimplemented!(),
        }
    }
}
