use std::{fmt, io::Cursor};

use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{buffer::Buffer, new_rd_length};

use super::{nsec3param::NSEC3PARAM, type_bitmaps::TypeBitMaps};

//-------------------------------------------------------------------------------------
// NSEC3 depends on NSEC3PARAM
//-------------------------------------------------------------------------------------

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
#[derive(Debug, Default, FromNetwork)]
pub struct NSEC3 {
    // transmistted through RR deserialization
    #[deser(ignore)]
    pub(super) rd_length: u16,

    params: NSEC3PARAM,
    hash_length: u8,
    owner_name: Buffer,

    #[deser(with_code( self.types = TypeBitMaps::new(self.rd_length - (self.params.len() + 1 + self.hash_length as usize) as u16); ))]
    types: TypeBitMaps,
}

// auto-implement new
new_rd_length!(NSEC3);

// impl<'a> FromNetworkOrder<'a> for NSEC3 {
//     fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
//         // don't deserialize the length
//         trace!("rd_length={}", self.rd_length);

//         // self.algorithm.deserialize_from(buffer)?;
//         // self.flags.deserialize_from(buffer)?;
//         // self.iterations.deserialize_from(buffer)?;
//         // self.salt_length.deserialize_from(buffer)?;

//         // self.salt = Buffer::new(self.salt_length as u16);
//         // self.salt.deserialize_from(buffer)?;
//         self.params.deserialize_from(buffer)?;

//         self.hash_length.deserialize_from(buffer)?;
//         self.owner_name = Buffer::new(self.hash_length);
//         self.owner_name.deserialize_from(buffer)?;

//         // finally, as the rd_length is passed through the length field, we can
//         // calculate the renaming length for types
//         // let types_length = self.rd_length - self.salt_length as u16 - self.hash_length as u16 - 6;
//         let types_length =
//             self.rd_length - (self.params.len() + 1 + self.hash_length as usize) as u16;
//         self.types.types_length = types_length;
//         //self.types = Buffer::new(length);
//         self.types.deserialize_from(buffer)?;

//         trace!("{:?}", self);

//         Ok(())
//     }
// }

impl fmt::Display for NSEC3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ", self.params, self.owner_name)?;

        for qt in &self.types.types {
            write!(f, "{} ", qt)?;
        }

        Ok(())
    }
}
