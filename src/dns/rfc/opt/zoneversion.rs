use std::fmt;

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use crate::dns::buffer::Buffer;
use crate::{opt_code, opt_data};

use serde::Serialize;

use super::{
    opt_rr::{OptionCode, OptionData},
    OptionDataValue,
};

// ZONEVERSION: https://www.rfc-editor.org/rfc/rfc9660.html
#[derive(Debug, Default, ToNetwork, Serialize)]
pub struct ZV {
    pub label_count: u8,
    pub r#type: u8,
    pub version: Buffer,
}

#[derive(Debug, Default, ToNetwork, Serialize)]
pub struct ZONEVERSION(pub Option<ZV>);

impl ZONEVERSION {
    pub fn new() -> Self {
        Self(Some(ZV::default()))
    }
}

impl From<ZV> for ZONEVERSION {
    fn from(zv: ZV) -> Self {
        Self(Some(zv))
    }
}

impl fmt::Display for ZONEVERSION {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(zv) = &self.0 {
            write!(f, "{}", zv.label_count)?;
            write!(f, "{}", zv.r#type)?;
            write!(f, "{}", zv.version.display())?;
        }

        Ok(())
    }
}

impl OptionDataValue for ZONEVERSION {
    // return the option code for the option data
    opt_code!(ZONEVERSION);

    // return option data length
    fn len(&self) -> u16 {
        0
    }

    // return None
    opt_data!();
}
