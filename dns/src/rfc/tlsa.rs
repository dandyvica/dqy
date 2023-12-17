use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use base64::{engine::general_purpose, Engine as _};

use crate::{buffer::Buffer, new_rd_length};

use super::algorithm::Algorithm;

// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Cert. Usage  |   Selector    | Matching Type |               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               /
// /                                                               /
// /                 Certificate Association Data                  /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, FromNetwork)]
pub(super) struct TLSA {
    #[deser(ignore)]
    rd_length: u16,

    cert_usage: u8,
    selector: u8,
    matching_type: u8,

    #[deser(with_code( self.data = Buffer::new(self.rd_length - 3); ))]
    data: Buffer,
}

// auto-implement new
new_rd_length!(TLSA);

impl fmt::Display for TLSA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.cert_usage, self.selector, self.matching_type, self.data
        )?;

        Ok(())
    }
}
