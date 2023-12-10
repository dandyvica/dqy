use std::{fmt, io::Cursor};

use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::buffer::Buffer;

use super::{algorithm::Algorithm, qtype::QType};

// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Hash Alg.   |     Flags     |          Iterations           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Salt Length  |                     Salt                      /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Hash Length  |             Next Hashed Owner Name            /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                         Type Bit Maps                         /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default)]
pub struct NSEC3 {
    pub(super) length: u16,

    algorithm: Algorithm,
    flags: u8,
    iterations: u16,
    salt_length: u8,
    salt: Buffer,
    hash_length: u8,
    owner_name: Buffer,
    types: Buffer,
}

struct TypeBitMaps(Vec<QType>);

impl<'a> FromNetworkOrder<'a> for NSEC3 {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        // don't deserialize the length
        trace!("===> length={}", self.length);

        self.algorithm.deserialize_from(buffer)?;
        self.flags.deserialize_from(buffer)?;
        self.iterations.deserialize_from(buffer)?;
        self.salt_length.deserialize_from(buffer)?;

        self.salt = Buffer::new(self.salt_length as u16);
        self.salt.deserialize_from(buffer)?;

        self.hash_length.deserialize_from(buffer)?;
        self.owner_name = Buffer::new(self.hash_length as u16);
        self.owner_name.deserialize_from(buffer)?;

        // finally, as the rd_length is passed through the length field, we can
        // calculate the renaming length for types
        let length = self.length - self.salt_length as u16 - self.hash_length as u16 - 6;
        self.types = Buffer::new(length);
        self.types.deserialize_from(buffer)?;

        trace!("===> DNSSEC={:?}", self);

        Ok(())
    }
}

// impl fmt::Display for DS {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(
//             f,
//             "key_tag: {} algorithm: {} digest_type: {} digest:{}",
//             self.key_tag, self.algorithm, self.digest_type, self.digest
//         )?;

//         // for c in &self.digest {
//         //     write!(f, "{:X?}", c)?;
//         // }

//         Ok(())
//     }
// }
