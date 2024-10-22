use std::fmt;

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use crate::buffer::Buffer;
use crate::{opt_code, opt_data};

use serde::Serialize;

use super::{
    opt_rr::{OptOptionCode, OptOptionData},
    OptionData,
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
        if self.0.is_some() {
            let buf = self.0.as_ref().unwrap();
            write!(f, "{:?}", buf)?;

            f.write_str("\"")?;
            write!(f, "{}", buf)?;
            f.write_str("\"")?;
        }

        Ok(())
    }
}

impl OptionData for NSID {
    // return the option code for the option data
    opt_code!(NSID);

    // return option data length
    fn len(&self) -> u16 {
        0
    }

    // return the option data enum arm
    opt_data!(NSID);
}
