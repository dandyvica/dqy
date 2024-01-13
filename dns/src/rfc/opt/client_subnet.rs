use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use serde::Serialize;

use crate::databuf::Buffer;

// https://www.rfc-editor.org/rfc/rfc7871
#[derive(Debug, Default, ToNetwork, FromNetwork, Serialize)]
pub struct ClientSubnet {
    pub(super) family: u16,
    pub(super) source_prefix_length: u8,
    pub(super) scope_prefix_length: u8,
    pub(super) address: Buffer,
}
