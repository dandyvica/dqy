use std::fmt;

use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use base64::{engine::general_purpose, Engine as _};

use crate::{buffer::Buffer, new_rd_length};

//-------------------------------------------------------------------------------------
// OPENPGPKEY
//-------------------------------------------------------------------------------------
#[derive(Debug, Default, FromNetwork)]
pub(super) struct OPENPGPKEY {
    // transmistted through RR deserialization
    #[deser(ignore)]
    rd_length: u16,

    #[deser(with_code( self.key = Buffer::new(self.rd_length ); ))]
    key: Buffer,
}

// auto-implement new
new_rd_length!(OPENPGPKEY);

impl fmt::Display for OPENPGPKEY {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        trace!("{:0x?}", self.key);
        write!(f, "{}", general_purpose::STANDARD.encode(&self.key))?;

        Ok(())
    }
}
