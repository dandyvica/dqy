use std::fmt;

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use serde::Serialize;

use super::{
    opt_rr::{OptionCode, OptionData},
    OptionDataValue,
};
use crate::dns::buffer::Buffer;
use crate::{opt_code, opt_data};

// Cookie: https://www.rfc-editor.org/rfc/rfc7873
// https://www.rfc-editor.org/rfc/rfc9018
#[derive(Debug, Default, ToNetwork, Serialize)]
pub struct COOKIE {
    pub client_cookie: [u8; 8],
    pub server_cookie: Option<Vec<u8>>,
}

impl fmt::Display for COOKIE {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} {:?}", self.client_cookie, self.server_cookie)
    }
}

impl OptionDataValue for COOKIE {
    // return the option code for the option data
    opt_code!(COOKIE);

    // return option data length
    fn len(&self) -> u16 {
        8
    }

    // return None
    opt_data!(COOKIE);
}
