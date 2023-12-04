use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::buffer::Buffer;

use super::algorithm::Algorithm;

// The RDATA for a DS RR consists of a 2 octet Key Tag field, a 1 octet
// Algorithm field, a 1 octet Digest Type field, and a Digest field.

//                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Key Tag             |  Algorithm    |  Digest Type  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                            Digest                             /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, FromNetwork)]
pub struct DS {
    key_tag: u16,
    algorithm: Algorithm,
    digest_type: u8,
    pub digest: Buffer,
}

impl fmt::Display for DS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "key_tag: {} algorithm: {} digest_type: {} digest:{}",
            self.key_tag, self.algorithm, self.digest_type, self.digest
        )?;

        // for c in &self.digest {
        //     write!(f, "{:X?}", c)?;
        // }

        Ok(())
    }
}
