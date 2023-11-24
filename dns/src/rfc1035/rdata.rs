use std::fmt::{self};

use type2network::ToNetworkOrder;

use super::{
    a::A, aaaa::AAAA, cname::CNAME, dnskey::DNSKEY, hinfo::HINFO, loc::LOC, mx::MX, ns::NS,
    ptr::PTR, soa::SOA, txt::TXT, ds::DS, rrsig::RRSIG,
};

use crate::rfc6891::opt::OPT;

#[derive(Debug)]
pub enum RData<'a> {
    A(A),
    AAAA(AAAA),
    CName(CNAME<'a>),
    HInfo(HINFO<'a>),
    Ptr(PTR<'a>),
    Opt(Option<Vec<OPT>>),
    Soa(SOA<'a>),
    Ns(NS<'a>),
    Txt(TXT<'a>),
    Mx(MX<'a>),
    Loc(LOC),
    DnsKey(DNSKEY),
    Ds(DS),
    Rrsig(RRSIG<'a>)
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
            RData::CName(a) => write!(f, "{}", a),
            RData::HInfo(a) => write!(f, "{}", a),
            RData::Ptr(a) => write!(f, "{}", a),
            RData::Ns(a) => write!(f, "{}", a),
            RData::Txt(a) => write!(f, "{}", a),
            RData::Soa(a) => write!(f, "{}", a),
            RData::Mx(a) => write!(f, "{}", a),
            RData::DnsKey(a) => write!(f, "{}", a),
            RData::Ds(a) => write!(f, "{}", a),
            RData::Rrsig(a) => write!(f, "{}", a),
            _ => unimplemented!(),
        }
    }
}
