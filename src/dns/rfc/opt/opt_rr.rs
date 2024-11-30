use std::{
    fmt,
    io::Cursor,
    ops::{Deref, DerefMut},
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use enum_from::{EnumDisplay, EnumTryFrom};
use log::trace;
use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use serde::Serialize;

use crate::dns::{
    buffer::Buffer,
    rfc::{
        domain::DomainName,
        opt::nsid::NSID,
        //qtype::QType, // resource_record::{OptClassTtl, OptOrElse, ResourceRecord},
    },
};

use super::{
    //client_subnet::ClientSubnet,
    client_subnet::ClientSubnet,
    cookie::COOKIE,
    extended::Extended,
    padding::Padding,
    report_chanel::ReportChannel,
    zoneversion::{ZONEVERSION, ZV},
};

// This OPT is the one which is sent in the query (additional record)
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
// https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2
//             +0 (MSB)                            +1 (LSB)
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 0: |                          OPTION-CODE                          |
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 2: |                         OPTION-LENGTH                         |
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 4: |                                                               |
//    /                          OPTION-DATA                          /
//    /                                                               /
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
#[derive(Debug, Default, ToNetwork, Serialize)]
pub struct OptOption {
    pub(crate) code: OptionCode,
    pub(crate) length: u16,
    pub(crate) data: Option<OptionData>,
}

impl fmt::Display for OptOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(data) = &self.data {
            write!(f, "{}   {}   {}", self.code, self.length, data)
        } else {
            write!(f, "{}   {}", self.code, self.length)
        }
    }
}

impl<'a> FromNetworkOrder<'a> for OptOption {
    #[allow(clippy::field_reassign_with_default)]
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        self.code.deserialize_from(buffer)?;
        self.length.deserialize_from(buffer)?;

        match self.code {
            OptionCode::NSID => {
                let mut buf: Buffer = Buffer::with_capacity(self.length);
                buf.deserialize_from(buffer)?;
                self.data = Some(OptionData::NSID(NSID::from(buf)));
            }
            OptionCode::Padding => {
                let mut buf: Buffer = Buffer::with_capacity(self.length);
                buf.deserialize_from(buffer)?;
                self.data = Some(OptionData::Padding(Padding::from(buf)));
            }
            OptionCode::Extended => {
                let mut info_code = 0u16;
                info_code.deserialize_from(buffer)?;
                let mut buf: Buffer = Buffer::with_capacity(self.length - 2);
                buf.deserialize_from(buffer)?;
                self.data = Some(OptionData::Extended(Extended::from((info_code, buf))));
            }
            OptionCode::ReportChannel => {
                let mut agent_domain = DomainName::default();
                agent_domain.deserialize_from(buffer)?;
                self.data = Some(OptionData::ReportChanel(ReportChannel::from(agent_domain)));
            }
            OptionCode::ZONEVERSION => {
                println!("inside ZV");
                let mut zv = ZV::default();
                zv.label_count.deserialize_from(buffer)?;
                zv.r#type.deserialize_from(buffer)?;
                let mut buf: Buffer = Buffer::with_capacity(self.length - 2);
                buf.deserialize_from(buffer)?;
                self.data = Some(OptionData::ZONEVERSION(ZONEVERSION::from(zv)));
            }
            OptionCode::EdnsClientSubnet => {
                let mut subnet = ClientSubnet::default();
                subnet.address = Buffer::with_capacity(self.length - 4);
                subnet.deserialize_from(buffer)?;
                self.data = Some(OptionData::ClientSubnet(subnet));
            }
            // OptionCode::Extended => {
            //     let mut extended = Extended::default();
            //     extended.extra_text = Buffer::with_capacity(self.length - 2);
            //     extended.deserialize_from(buffer)?;
            //     self.data = OptOptionData::Extended(extended);
            // }
            _ => unimplemented!("option code <{}> is not yet implemented", self.code),
        }

        trace!("OptOption deserialize: {:#?}", self);
        Ok(())
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq, EnumTryFrom, EnumDisplay, ToNetwork, FromNetwork, Serialize)]
#[repr(u16)]
#[from_network(TryFrom)]
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
    ReportChannel = 18,
    ZONEVERSION = 19,
    Umbrella = 20292, // Ident	Optional	[https://developer.cisco.com/docs/cloud-security/#!integrating-network-devices/rdata-description][Cisco_CIE_DNS_team]
    DeviceID = 26946, // Optional	[https://developer.cisco.com/docs/cloud-security/#!network-devices-getting-started/response-codes][Cisco_CIE_DNS_team]
}

#[derive(Debug, ToNetwork, Serialize)]
pub enum OptionData {
    NSID(NSID),
    COOKIE(COOKIE),
    Padding(Padding),
    ClientSubnet(ClientSubnet),
    // DAU(DAU),
    // DHU(DHU),
    // N3U(N3U),
    // EdnsKeyTag(EdnsKeyTag),
    Extended(Extended),
    ReportChanel(ReportChannel),
    ZONEVERSION(ZONEVERSION),
}

impl Default for OptionData {
    fn default() -> Self {
        OptionData::NSID(NSID::default())
    }
}

impl fmt::Display for OptionData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptionData::NSID(n) => write!(f, "{}", n)?,
            OptionData::Padding(p) => write!(f, "{}", p)?,
            OptionData::Extended(p) => write!(f, "{}", p)?,
            OptionData::ClientSubnet(p) => write!(f, "{} {}", p.family, p.address)?,
            OptionData::ReportChanel(p) => write!(f, "{}", p)?,
            OptionData::ZONEVERSION(p) => write!(f, "{}", p)?,
            _ => unimplemented!("EDNS option not yet implemented"),
        }
        Ok(())
    }
}

// list of options which are appended to the RDATA for the OPT RR
#[derive(Debug, Default, Serialize, ToNetwork, FromNetwork)]
pub struct OptionList(Vec<OptOption>);

impl OptionList {
    pub fn new(v: Vec<OptOption>) -> Self {
        Self(v)
    }
}

impl Deref for OptionList {
    type Target = Vec<OptOption>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for OptionList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// IntoIterator to benefit from already defined iterator on Vec
impl<'a> IntoIterator for &'a OptionList {
    type Item = &'a OptOption;
    type IntoIter = std::slice::Iter<'a, OptOption>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl fmt::Display for OptionList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for opt in &self.0 {
            write!(f, "<{}>", opt)?;
        }

        Ok(())
    }
}
