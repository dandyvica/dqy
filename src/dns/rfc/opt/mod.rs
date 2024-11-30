// Value	Name	Status	Reference
// 8	edns-client-subnet	Optional	[RFC7871]
// 9	EDNS EXPIRE	Optional	[RFC7314]
// 10	COOKIE	Standard	[RFC7873]
// 11	edns-tcp-keepalive	Standard	[RFC7828]
// 13	CHAIN	Standard	[RFC7901]
// 15	Extended DNS Error	Standard	[RFC8914]
// 16	EDNS-Client-Tag	Optional	[draft-bellis-dnsop-edns-tags]
// 17	EDNS-Server-Tag	Optional	[draft-bellis-dnsop-edns-tags]
// 18-20291	Unassigned
// 20292	Umbrella Ident	Optional	[https://developer.cisco.com/docs/cloud-security/#!integrating-network-devices/rdata-description][Cisco_CIE_DNS_team]
// 20293-26945	Unassigned
// 26946	DeviceID	Optional	[https://developer.cisco.com/docs/cloud-security/#!network-devices-getting-started/response-codes][Cisco_CIE_DNS_team]
// 26947-65000	Unassigned
// 65001-65534	Reserved for Local/Experimental Use		[RFC6891]
// 65535	Reserved for future expansion		[RFC6891]

use self::opt_rr::{OptionCode, OptionData};

pub mod client_subnet;
pub mod cookie;
//pub mod dau_dhu_n3u;
pub mod extended;
pub mod nsid;
pub mod opt_rr;
pub mod padding;
pub mod report_chanel;
pub mod zoneversion;

pub trait OptionDataValue {
    // return the option code for the option data
    fn code(&self) -> OptionCode;

    // return option data length
    fn len(&self) -> u16;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // return the option data enum arm
    fn data(self) -> Option<OptionData>;
}

// macro helpers to define code() et data() easily
#[macro_export]
macro_rules! opt_code {
    ($opt:ident) => {
        fn code(&self) -> OptionCode {
            OptionCode::$opt
        }
    };
}

#[macro_export]
macro_rules! opt_data {
    ($opt:ident) => {
        fn data(self) -> Option<OptionData> {
            Some(OptionData::$opt(self))
        }
    };

    () => {
        fn data(self) -> Option<OptionData> {
            None
        }
    };
}
