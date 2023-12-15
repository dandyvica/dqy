// some RRs represent the number of seconds since EPOCH

use std::fmt;

use chrono::NaiveDateTime;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

#[derive(Debug, Default, PartialEq, FromNetwork)]
pub struct DateTime(u32);

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let date_time = NaiveDateTime::from_timestamp_opt(self.0 as i64, 0)
            .unwrap()
            .format("%Y%m%d%H%M%S");
        write!(f, "{}", date_time)?;

        Ok(())
    }
}
