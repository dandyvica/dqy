use std::{fmt, num::ParseIntError};

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use serde::Serialize;

use super::{
    opt_rr::{OptionCode, OptionData},
    OptionDataValue,
};
use crate::{opt_code, opt_data, opt_len};

// Cookie: https://www.rfc-editor.org/rfc/rfc7873
// https://www.rfc-editor.org/rfc/rfc9018
#[derive(Debug, Default, ToNetwork, Serialize)]
pub struct COOKIE {
    pub client_cookie: [u8; 8],
    pub server_cookie: Option<Vec<u8>>,
}

impl COOKIE {
    // prepare a random cookie
    pub fn random() -> Self {
        Self {
            client_cookie: rand::random(),
            server_cookie: None,
        }
    }
}

impl From<&str> for COOKIE {
    fn from(cookie_string: &str) -> Self {
        match cookie_string.len() {
            // cookie is either empty, or less than 16 chars
            0..=16 => COOKIE::random(),

            // otherwise take only 16 chars
            _ => {
                let mut cookie = COOKIE::default();

                // if hex encoding is successful
                if let Ok(v) = decode_cookie(cookie_string) {
                    cookie.client_cookie[0] = v[0];
                    cookie.client_cookie[1] = v[1];
                    cookie.client_cookie[2] = v[2];
                    cookie.client_cookie[3] = v[3];
                    cookie.client_cookie[4] = v[4];
                    cookie.client_cookie[5] = v[5];
                    cookie.client_cookie[6] = v[6];
                    cookie.client_cookie[7] = v[7];

                    cookie
                }
                // error, so fall back to a random one
                else {
                    COOKIE::random()
                }
            }
        }
    }
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
    opt_len!(8);

    // return None
    opt_data!(COOKIE);
}

// encode an hex string into a vector
fn decode_cookie(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..16)
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
