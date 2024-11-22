use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use serde::Serialize;

use crate::{opt_code, opt_data};

use super::{
    opt_rr::{OptOptionCode, OptOptionData},
    OptionData,
};

// useful macro to auto define DAU, DHU & N3U which are the same
macro_rules! opt {
    ($opt:ident, $t:ty) => {
        #[derive(Debug, Default, ToNetwork, Serialize)]
        pub struct $opt(Vec<$t>);

        impl From<&[$t]> for $opt {
            fn from(buf: &[$t]) -> Self {
                Self(buf.to_vec())
            }
        }

        impl std::ops::Deref for $opt {
            type Target = Vec<$t>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl OptionData for $opt {
            // return the option code for the option data
            opt_code!($opt);

            // return option data length
            fn len(&self) -> u16 {
                self.0.len() as u16
            }

            // return the option data enum arm
            opt_data!($opt);
        }
    };
}

// https://www.rfc-editor.org/rfc/rfc6975.html
// impl DAU, DHU, N3U
opt!(DAU, u8);
opt!(DHU, u8);
opt!(N3U, u8);

// impl edns-key-tag
opt!(EdnsKeyTag, u16);
