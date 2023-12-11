#[allow(clippy::unnecessary_cast)]
pub mod char_string;
pub mod domain;
pub mod flags;
pub mod header;
pub mod opcode;
pub mod packet_type;
pub mod qclass;
pub mod qtype;
pub mod question;
pub mod resource_record;
pub mod response_code;
// all RRs
pub mod a;
pub mod aaaa;
pub mod algorithm;
pub mod cname;
pub mod dnskey;
pub mod ds;
pub mod hinfo;
pub mod loc;
pub mod mx;
pub mod ns;
pub mod nsec3;
pub mod opt;
pub mod ptr;
pub mod query;
pub mod rdata;
pub mod response;
pub mod rrsig;
pub mod soa;
pub mod txt;

// a helper macro to generate the new() method for those struct having the rd_length field
// helper macro to ease returning the internal DNS errors
#[macro_export]
macro_rules! new_rd_length {
    ($struct:ty) => {
        impl $struct {
            pub fn new(len: u16) -> Self {
                let mut x = Self::default();
                x.rd_length = len;

                x
            }
        }
    };
}
