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
pub mod afsdb;
pub mod algorithm;
pub mod apl;
pub mod caa;
pub mod cert;
pub mod cname;
pub mod csync;
pub mod dhcid;
pub mod dnskey;
pub mod ds;
pub mod eui48;
pub mod eui64;
pub mod hinfo;
pub mod hip;
pub mod ipseckey;
pub mod kx;
pub mod loc;
pub mod mx;
pub mod naptr;
pub mod ns;
pub mod nsec;
pub mod nsec3;
pub mod nsec3param;
pub mod openpgpkey;
pub mod opt;
pub mod ptr;
pub mod query;
pub mod rdata;
pub mod response;
pub mod rp;
pub mod rrlist;
pub mod rrsig;
pub mod soa;
pub mod srv;
pub mod sshfp;
pub mod svcb;
// pub mod tkey;
pub mod tlsa;
pub mod txt;
pub mod type_bitmaps;
pub mod uri;
pub mod wallet;
pub mod zonemd;

//
pub(crate) trait DataLength {
    fn len(&self) -> u16;
}

// a helper macro to generate the new() method for those struct having the rd_length field
// helper macro to ease returning the internal DNS errors
#[macro_export]
macro_rules! new_rd_length {
    // this macro works also for struct with lifetimes
    // see: https://stackoverflow.com/questions/41603424/rust-macro-accepting-type-with-generic-parameters
    // length is transmitted when calling macro get_rr!() but is already deserialized
    ($rr:ident $(< $lf:lifetime >)? ) => {
        impl $(< $lf >)? $rr $(< $lf >)? {
            pub fn new(len: u16) -> Self {
                log::trace!("new_rd_length!({}): receive length {}", stringify!($rr), len);

                let mut x = Self::default();
                x.rd_length = len;

                x
            }
        }
    };
}
