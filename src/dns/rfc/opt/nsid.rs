use std::fmt;

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use crate::dns::buffer::Buffer;
use crate::{opt_code, opt_data, opt_len};

use serde::Serialize;

use super::{
    opt_rr::{OptionCode, OptionData},
    OptionDataValue,
};

// NSID: https://www.rfc-editor.org/rfc/rfc5001.html
#[derive(Debug, Default, ToNetwork, Serialize)]
pub struct NSID(Option<Buffer>);

impl From<Buffer> for NSID {
    fn from(buf: Buffer) -> Self {
        Self(Some(buf))
    }
}

impl fmt::Display for NSID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(b) = &self.0 {
            write!(f, "{}", b.display())?
        }

        Ok(())
    }
}

impl OptionDataValue for NSID {
    // return the option code for the option data
    opt_code!(NSID);

    // return option data length
    opt_len!(0);

    // return None
    opt_data!();
}
