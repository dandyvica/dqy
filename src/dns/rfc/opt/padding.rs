use std::fmt;

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use serde::Serialize;

use crate::{dns::buffer::Buffer, opt_code, opt_data};

use super::{
    opt_rr::{OptionCode, OptOptionData},
    OptionData,
};

// https://www.rfc-editor.org/rfc/rfc7830.html
#[derive(Debug, Default, ToNetwork, Serialize)]
pub struct Padding(Option<Buffer>);

impl Padding {
    pub fn new(len: u16) -> Self {
        if len == 0 {
            Self(None)
        } else {
            let buf = Buffer::with_capacity(len);
            //buf.fill(0);
            Self(Some(buf))
        }
    }
}

impl From<Buffer> for Padding {
    fn from(buf: Buffer) -> Self {
        Self(Some(buf))
    }
}

impl fmt::Display for Padding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_some() {
            let buf = self.0.as_ref().unwrap();
            write!(f, "{:?}", buf)?;
            write!(f, "{}", buf)?;
        }

        Ok(())
    }
}

impl OptionData for Padding {
    // return the option code for the option data
    opt_code!(Padding);

    // return option data length
    fn len(&self) -> u16 {
        if self.0.is_none() {
            0
        } else {
            self.0.as_ref().unwrap().len() as u16
        }
    }

    // return the option data enum arm
    opt_data!(Padding);
}
