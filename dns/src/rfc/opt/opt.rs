use std::{fmt, io::Cursor};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use enum_from::{EnumDisplay, EnumTryFrom};
use log::trace;
use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use crate::{
    databuf::Buffer,
    either_or::EitherOr,
    rfc::{
        opt::{self, nsid::NSID},
        qtype::QType,
        resource_record::ResourceRecord,
    },
};

use super::{
    client_subnet::ClientSubnet,
    cookie::COOKIE,
    dau_dhu_n3u::{EdnsKeyTag, DAU, DHU, N3U},
    padding::Padding,
    OptionData,
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
pub type OptQuery<'a> = ResourceRecord<'a, Vec<OptOption>>;

impl<'a> OptQuery<'a> {
    #[allow(clippy::field_reassign_with_default)]
    pub fn new(bufsize: u16) -> Self {
        let mut opt = OptQuery::default();

        // QType = 41
        opt.r#type = QType::OPT;

        // class is UDP payload size
        opt.class = EitherOr::new_right(bufsize);

        opt
    }

    // set DNSSEC bit to 1
    #[allow(clippy::field_reassign_with_default)]
    pub fn set_dnssec(&mut self) {
        let mut opt_ttl = OptTTL::default();
        opt_ttl.flags = 0x8000;

        self.ttl = EitherOr::new_right(opt_ttl);
    }

    // add another OPT data in the OPT record
    pub fn push_option(&mut self, option: OptOption) {
        // 4 corresponds to option code and length
        self.rd_length += 4 + option.length;
        self.r_data.push(option);
    }

    pub fn add_option<T: OptionData>(&mut self, data: T) {
        // build the option structure
        let mut option = OptOption::default();
        option.code = data.code();
        option.length = data.len();
        option.data = data.data();

        trace!("OPTION:{:?}", option);

        // add in the list of options
        self.rd_length += 4 + option.length;
        self.r_data.push(option);
    }

    // #[allow(clippy::field_reassign_with_default)]
    // pub fn set_edns_nsid(&mut self) {
    //     let mut nsid = OptOption::default();
    //     nsid.code = OptOptionCode::NSID;

    //     self.push_option(nsid);
    // }
}

// https://www.rfc-editor.org/rfc/rfc6891#section-6.1.3
// +0 (MSB)                            +1 (LSB)
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 0: |         EXTENDED-RCODE        |            VERSION            |
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 2: | DO|                           Z                               |
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, ToNetwork, FromNetwork)]
pub struct OptTTL {
    pub(super) extended_rcode: u8,
    pub(super) version: u8,
    pub(super) flags: u16,
}

impl fmt::Display for OptTTL {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({} {} {})",
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
    pub(super) code: OptOptionCode,
    pub(crate) length: u16,
    pub(super) data: OptOptionData,
}

impl fmt::Display for OptOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}-{}-<{}>)", self.code, self.length, self.data)
    }
}

impl<'a> FromNetworkOrder<'a> for OptOption {
    #[allow(clippy::field_reassign_with_default)]
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        self.code.deserialize_from(buffer)?;
        self.length.deserialize_from(buffer)?;

        match self.code {
            OptOptionCode::NSID => {
                let mut buf: Buffer = Buffer::with_capacity(self.length);
                buf.deserialize_from(buffer)?;
                self.data = OptOptionData::NSID(NSID::from(buf));
            }
            OptOptionCode::Padding => {
                let mut buf: Buffer = Buffer::with_capacity(self.length);
                buf.deserialize_from(buffer)?;
                self.data = OptOptionData::Padding(Padding::from(buf));
            }
            OptOptionCode::EdnsClientSubnet => {
                let mut subnet = ClientSubnet::default();
                subnet.address = Buffer::with_capacity(self.length - 4);
                subnet.deserialize_from(buffer)?;
                self.data = OptOptionData::ClientSubnet(subnet);
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
    Padding(Padding),
    ClientSubnet(ClientSubnet),
    DAU(DAU),
    DHU(DHU),
    N3U(N3U),
    EdnsKeyTag(EdnsKeyTag),
}

impl Default for OptOptionData {
    fn default() -> Self {
        OptOptionData::NSID(NSID::default())
    }
}

impl fmt::Display for OptOptionData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptOptionData::NSID(n) => write!(f, "{}", n)?,
            OptOptionData::Padding(p) => write!(f, "{}", p)?,
            OptOptionData::ClientSubnet(p) => write!(f, "{} {}", p.family, p.address)?,
            _ => unimplemented!("EDNS option not yet implemented"),
        }
        Ok(())
    }
}
