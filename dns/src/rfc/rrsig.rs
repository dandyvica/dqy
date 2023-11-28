use std::fmt;

use base64::{engine::general_purpose, Engine as _};

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::buffer::Buffer;

use super::{domain::DomainName, rtype::RType};

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
pub struct RRSIG<'a> {
    pub type_covered: RType,
    pub algorithm: u8,
    pub labels: u8,
    pub ttl: u32,
    pub sign_expiration: u32,
    pub sign_inception: u32,
    pub key_tag: u16,

    #[deser(no)]
    pub name: DomainName<'a>,
    #[deser(no)]
    pub signature: Buffer,
}

impl<'a> fmt::Display for RRSIG<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ", self.type_covered, self.name)?;

        let b64 = general_purpose::STANDARD.encode(&self.signature);
        write!(f, "{}", b64)?;

        Ok(())
    }
}