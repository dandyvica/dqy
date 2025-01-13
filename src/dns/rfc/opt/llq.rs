use std::fmt;

use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use serde::Serialize;

use super::{
    opt_rr::{OptionCode, OptionData},
    OptionDataValue,
};
use crate::{opt_code, opt_data, opt_len};

// https://datatracker.ietf.org/doc/html/rfc8764
#[derive(Debug, Default, ToNetwork, FromNetwork, Serialize)]
pub struct LLQ {
    pub(super) version: u16,
    pub(super) opcode: u16,
    pub(super) error: u16,
    pub(super) id: u64,
    pub(super) lease: u32,
}

impl fmt::Display for LLQ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {}",
            self.version, self.opcode, self.error, self.id, self.lease
        )
    }
}

impl OptionDataValue for LLQ {
    // return the option code for the option data
    opt_code!(LLQ);

    // return option data length
    opt_len!(18);

    // return None
    opt_data!(LLQ);
}
