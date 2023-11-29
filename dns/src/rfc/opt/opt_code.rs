use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

#[derive(Debug, Default, Copy, Clone, PartialEq, ToNetwork, FromNetwork)]
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
