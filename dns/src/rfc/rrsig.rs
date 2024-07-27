use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{buffer::Buffer, date_time::DnsDateTime, new_rd_length};

use super::{algorithm::Algorithm, domain::DomainName, qtype::QType};

// The RDATA for an RRSIG RR consists of a 2 octet Type Covered field, a
// 1 octet Algorithm field, a 1 octet Labels field, a 4 octet Original
// TTL field, a 4 octet Signature Expiration field, a 4 octet Signature
// Inception field, a 2 octet Key tag, the Signer's Name field, and the
// Signature field.

//                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Type Covered           |  Algorithm    |     Labels    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Original TTL                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Signature Expiration                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Signature Inception                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |            Key Tag            |                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                            Signature                          /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, FromNetwork)]
pub struct RRSIG {
    #[deser(ignore)]
    pub(super) rd_length: u16,

    pub type_covered: QType,
    pub algorithm: Algorithm,
    pub labels: u8,
    pub ttl: u32,
    pub sign_expiration: DnsDateTime,
    pub sign_inception: DnsDateTime,
    pub key_tag: u16,

    // will be deserialized locally
    // #[deser(ignore)]
    pub name: DomainName,

    #[deser(with_code( self.signature = Buffer::with_capacity(self.rd_length - 18 - self.name.len() as u16); ))]
    pub signature: Buffer,
}

// auto-implement new
new_rd_length!(RRSIG);

impl fmt::Display for RRSIG {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {}",
            self.type_covered,
            self.algorithm,
            self.name,
            self.sign_expiration,
            self.sign_inception,
            self.key_tag,
            self.signature.to_b64()
        )
    }
}

// Custom serialization
use serde::{ser::SerializeMap, Serialize, Serializer};
impl Serialize for RRSIG {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(7))?;
        seq.serialize_entry("type_covered", &self.type_covered)?;
        seq.serialize_entry("algorithm", &self.algorithm.to_string())?;
        seq.serialize_entry("labels", &self.labels)?;
        seq.serialize_entry("ttl", &self.ttl)?;

        seq.serialize_entry("sign_expiration", &self.sign_expiration.to_string())?;
        seq.serialize_entry("sign_inception", &self.sign_inception.to_string())?;
        seq.serialize_entry("name", &self.name)?;

        seq.serialize_entry("signature", &self.signature.to_b64())?;
        seq.end()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        rfc::{rdata::RData, response::Response},
        test_rdata,
        tests::get_packets,
    };

    use type2network::FromNetworkOrder;

    use super::RRSIG;

    test_rdata!(
        rdata,
        "./tests/rrsig.pcap",
        false,
        1,
        RData::RRSIG,
        (|x: &RRSIG, i: usize| {
            match i {
                0 => assert_eq!(x.to_string(), "TXT ECDSAP256SHA256 dns.netmeister.org. 20240105225356 20231222220918 61102 1dKF+G83fLep6Hk1ylM0c5VEkoj8ZTHQj9O30iH0Ldz2+bisTRE7WtDVXCnz0OHL8OOnwpGTLZItfj9kpuvpDw=="),
                1 => assert_eq!(x.to_string(), "NSEC ECDSAP256SHA256 dns.netmeister.org. 20240105225356 20231222220918 61102 OQ2AxONxJbZG2MtoEp+QrmolHnTlWxchO0zmUzgBAdTPDeOJmjfVqpM0MOfOnZ3qk1oss+EyhYwNvaFYSo3fpw=="),
                _ => panic!("data not is the pcap file"),
            }
        })
    );
}
