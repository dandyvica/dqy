// use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{dns::buffer::Buffer, new_rd_length};

use super::domain::DomainName;

// https://www.rfc-editor.org/rfc/rfc2930#section-2
// Algorithm:   domain
// Inception:   u_int32_t
// Expiration:  u_int32_t
// Mode:        u_int16_t
// Error:       u_int16_t
// Key Size:    u_int16_t
// Key Data:    octet-stream
// Other Size:  u_int16_t
// Other Data:  octet-stream  undefined by this specification
#[derive(Debug, Default, FromNetwork)]
pub struct TKEY {
    #[from_network(ignore)]
    pub(super) rd_length: u16,

    algorithm: DomainName,
    inception: u32,
    expiration: u32,
    mode: u16,
    error: u16,

    key_size: u16,
    #[from_network(with_code( self.key_data = Buffer::with_capacity(self.key_size); ))]
    key_data: Buffer,

    other_size: u16,
    #[from_network(with_code( self.key_data = Buffer::with_capacity(self.other_size); ))]
    other_data: Buffer,
}

// auto-implement new
new_rd_length!(TKEY);

// impl fmt::Display for TKEY {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(
//             f,
//             "{} {} {} {}",
//             self.key_tag, self.algorithm, self.digest_type, self.digest
//         )?;

//         // for c in &self.digest {
//         //     write!(f, "{:X?}", c)?;
//         // }

//         Ok(())
//     }
// }
