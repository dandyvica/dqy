use std::fmt;

use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{buffer::Buffer, new_rd_length};

//-------------------------------------------------------------------------------------
// CAA
//-------------------------------------------------------------------------------------

// +0-1-2-3-4-5-6-7-|0-1-2-3-4-5-6-7-|
// | Flags          | Tag Length = n |
// +----------------+----------------+...+---------------+
// | Tag char 0     | Tag char 1     |...| Tag char n-1  |
// +----------------+----------------+...+---------------+
// +----------------+----------------+.....+----------------+
// | Value byte 0   | Value byte 1   |.....| Value byte m-1 |
// +----------------+----------------+.....+----------------+
#[derive(Debug, Default, FromNetwork)]
pub(super) struct CAA {
    // transmistted through RR deserialization
    #[deser(ignore)]
    rd_length: u16,

    flags: u8,
    tag_length: u8,

    #[deser(with_code( self.tag_key = Buffer::new(self.tag_length); ))]
    tag_key: Buffer,

    #[deser(with_code( self.tag_value = Buffer::new(self.rd_length - self.tag_length as u16 - 2 ); ))]
    tag_value: Buffer,
}

// auto-implement new
new_rd_length!(CAA);

impl fmt::Display for CAA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.flags,
            self.tag_length,
            self.tag_key.to_string(),
            self.tag_value.to_string()
        )?;

        Ok(())
    }
}
