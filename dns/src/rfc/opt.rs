use std::{default, fmt, io::Cursor};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use enum_from::{EnumDisplay, EnumTryFrom};
use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use crate::{buffer::Buffer, either::EitherOr};

use super::{nsid::NSID, qtype::QType, resource_record::ResourceRecord};

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
//#[derive(Debug, Default)]
pub type OptQuery<'a> = ResourceRecord<'a, Vec<OptOption>>;

impl<'a> ResourceRecord<'a, Vec<OptOption>> {
    pub fn new(bufsize: Option<u16>) -> Self {
        let mut opt = OptQuery::default();
        opt.r#type = QType::OPT;
        opt.class = EitherOr::new_right(bufsize.unwrap_or(1232));

        opt
    }

    // add another OPT data in the OPT record
    pub fn push_option(&mut self, option: OptOption) {
        // 4 corresponds to option code and length
        self.rd_length += 4 + option.length;
        self.r_data.push(option);
    }

    pub fn set_edns_nsid(&mut self) {
        let mut nsid = OptOption::default();
        nsid.code = OptOptionCode::NSID;

        self.push_option(nsid);
    }
}

// https://www.rfc-editor.org/rfc/rfc6891#section-6.1.3
// +0 (MSB)                            +1 (LSB)
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 0: |         EXTENDED-RCODE        |            VERSION            |
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 2: | DO|                           Z                               |
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
#[derive(Debug, Default, Eq, PartialEq, ToNetwork, FromNetwork)]
pub struct OptTTL {
    pub extended_rcode: u8,
    pub version: u8,
    pub flags: u16,
}

impl<'a> fmt::Display for OptTTL {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "extended_rcode:{} version:{} flags:{}",
            self.extended_rcode, self.version, self.flags
        )
    }
}

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
#[derive(Debug, Default, ToNetwork)]
pub struct OptOption {
    pub code: OptOptionCode,
    pub length: u16,
    pub data: OptOptionData,
}

impl<'a> fmt::Display for OptOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<10} {:<10} {}",
            self.code.to_string(),
            self.length,
            self.data
        )
    }
}

impl<'a> FromNetworkOrder<'a> for OptOption {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        self.code.deserialize_from(buffer)?;
        self.length.deserialize_from(buffer)?;

        match self.code {
            OptOptionCode::NSID => {
                let mut buf: Buffer = Buffer::new(self.length);
                buf.deserialize_from(buffer)?;
                self.data = OptOptionData::NSID(NSID::from(buf));
            }
            _ => unimplemented!("option code {} is not yet implemented", self.code),
        }
        Ok(())
    }
}

#[derive(
    Debug, Default, Copy, Clone, PartialEq, EnumTryFrom, EnumDisplay, ToNetwork, FromNetwork,
)]
#[repr(u16)]
pub enum OptOptionCode {
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

#[derive(Debug, ToNetwork)]
pub enum OptOptionData {
    NSID(NSID),
    COOKIE(COOKIE),
}

impl Default for OptOptionData {
    fn default() -> Self {
        OptOptionData::NSID(NSID::default())
    }
}

impl<'a> fmt::Display for OptOptionData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptOptionData::NSID(n) => write!(f, "{}", n)?,
            _ => unimplemented!(),
        }
        Ok(())
    }
}

//---------------------------------------------------------------------------
// all option data are specified here
//---------------------------------------------------------------------------

// Cookie: https://www.rfc-editor.org/rfc/rfc5001.html
#[derive(Debug, Default, ToNetwork)]
pub struct COOKIE {
    client_cookie: Vec<u8>,
    server_cookie: Option<Vec<u8>>,
}