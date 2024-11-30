use std::fmt;

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use crate::dns::rfc::domain::DomainName;
use crate::{opt_code, opt_data};

use serde::Serialize;

use super::{
    opt_rr::{OptionCode, OptionData},
    OptionDataValue,
};

// ReportChanel: https://www.rfc-editor.org/rfc/rfc9567.html
#[derive(Debug, Default, ToNetwork, Serialize)]
pub struct ReportChannel(DomainName);

impl From<DomainName> for ReportChannel {
    fn from(dn: DomainName) -> Self {
        Self(dn)
    }
}

impl fmt::Display for ReportChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl OptionDataValue for ReportChannel {
    // return the option code for the option data
    opt_code!(ReportChannel);

    // return option data length
    fn len(&self) -> u16 {
        0
    }

    // return None
    opt_data!();
}
