// some RRs represent the number of seconds since EPOCH

use std::fmt;

use chrono::DateTime;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

#[derive(Debug, Default, PartialEq, FromNetwork)]
pub struct DnsDateTime(u32);

impl fmt::Display for DnsDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let date_time = DateTime::from_timestamp(self.0 as i64, 0)
            .unwrap()
            .format("%Y%m%d%H%M%S");
        write!(f, "{}", date_time)?;

        Ok(())
    }
}

// Custom serialization
use serde::{Serialize, Serializer};
impl Serialize for DnsDateTime {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datetime() {
        let dt = DnsDateTime(0);
        assert_eq!(dt.to_string(), "19700101000000");
    }
}
