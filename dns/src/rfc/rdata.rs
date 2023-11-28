use std::fmt::{self};

use type2network::ToNetworkOrder;

use super::{
    a::A, aaaa::AAAA, cname::CNAME, dnskey::DNSKEY, ds::DS, hinfo::HINFO, loc::LOC, mx::MX, ns::NS,
    ptr::PTR, rrsig::RRSIG, soa::SOA, txt::TXT,
};

use crate::{buffer::Buffer, rfc::opt::OPT};

#[derive(Debug)]
pub enum RData<'a> {
    A(A),
    AAAA(AAAA),
    CNAME(CNAME<'a>),
    HINFO(HINFO<'a>),
    PTR(PTR<'a>),
    OPT(Option<Vec<OPT>>),
    SOA(SOA<'a>),
    NS(NS<'a>),
    TXT(TXT<'a>),
    MX(MX<'a>),
    LOC(LOC),
    DNSKEY(DNSKEY),
    DS(DS),
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
            RData::RRSIG(a) => write!(f, "{}", a),
            RData::UNKNOWN(a) => write!(f, "{}", a),
            _ => unimplemented!(),
        }
    }
}
