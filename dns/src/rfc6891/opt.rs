use std::fmt;
use std::io::Cursor;
use std::ops::Deref;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use crate::rfc1035::{qclass::Class, qtype::QType, resource_record::MetaRR};

pub struct OptRR<'a>(pub MetaRR<'a>);

impl<'a> OptRR<'a> {
    pub fn new(bufsize: Option<u16>) -> Self {
        let mut opt = MetaRR::default();
        opt.r#type = QType::OPT;
        opt.class = Class::Payload(bufsize.unwrap_or(1232));

        OptRR(opt)
    }

    pub fn set_edns_nsid(&mut self) -> std::io::Result<()> {
        let mut opt = OPT::default();
        opt.code = OptionCode::NSID as u16;

        self.0.rd_length += opt.serialize_to(&mut self.0.r_data)? as u16;

        Ok(())
    }
}

impl<'a> Deref for OptRR<'a> {
    type Target = MetaRR<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Default, FromNetwork)]
pub struct ExtendedRcode {
    pub extented_rcode: u8,
    pub version: u8,
    pub doz: u16,
}

#[derive(Debug, Default, Copy, Clone, PartialEq, ToNetwork, FromNetwork)]
pub enum OptionCode {
    #[default]
    LLQ = 1, // Optional	[RFC8764]
    UL = 2,                // On-hold	[http://files.dns-sd.org/draft-sekar-dns-ul.txt]
    NSID = 3,              // Standard	[RFC5001]
    Reserved = 4,          // 	[draft-cheshire-edns0-owner-option]
    DAU = 5,               // Standard	[RFC6975]
    DHU = 6,               // Standard	[RFC6975]
    N3U = 7,               // Standard	[RFC6975]
    EdnsClientSubnet = 8,  //	Optional	[RFC7871]
    EDNS = 9,              // EXPIRE	Optional	[RFC7314]
    COOKIE = 10,           // Standard	[RFC7873]
    EdnsTcpKeepalive = 11, //	Standard	[RFC7828]
    Padding = 12,          // Standard	[RFC7830]
    CHAIN = 13,            // Standard	[RFC7901]
    EdnsKeyTag = 14,       //	Optional	[RFC8145]
    Extended = 15,         // DNS Error	Standard	[RFC8914]
    EdnsClientTag = 16,    //	Optional	[draft-bellis-dnsop-edns-tags]
    EdnsServerTag = 17,    //	Optional	[draft-bellis-dnsop-edns-tags]
    Umbrella = 20292, // Ident	Optional	[https://developer.cisco.com/docs/cloud-security/#!integrating-network-devices/rdata-description][Cisco_CIE_DNS_team]
    DeviceID = 26946, // Optional	[https://developer.cisco.com/docs/cloud-security/#!network-devices-getting-started/response-codes][Cisco_CIE_DNS_team]
}

#[derive(Debug, Default, ToNetwork)]
pub struct OPT {
    pub code: u16,
    pub length: u16,
    pub data: Vec<u8>,
}

impl<'a> FromNetworkOrder<'a> for OPT {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        self.code.deserialize_from(buffer)?;
        self.length.deserialize_from(buffer)?;

        self.data = Vec::with_capacity(self.length as usize);
        self.data.deserialize_from(buffer)?;

        Ok(())
    }
}

impl fmt::Display for OPT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "code={}, length={}", self.code, self.length)
    }
}
