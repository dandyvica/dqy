use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use serde::Serialize;

use crate::dns::buffer::Buffer;

// https://www.rfc-editor.org/rfc/rfc7871
#[derive(Debug, Default, ToNetwork, FromNetwork, Serialize)]
pub struct Extended {
    pub(super) info_code: u16,
    pub(super) extra_text: Buffer,
}
