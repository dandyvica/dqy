use std::fmt;

// use log::trace;
use byteorder::{BigEndian, ReadBytesExt};
use enum_from::{EnumDisplay, EnumFromStr, EnumTryFrom};
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::{ser::SerializeMap, Serialize, Serializer};

use crate::{buffer::Buffer, new_rd_length};

// https://www.rfc-editor.org/rfc/rfc4398.html#section-2.2
#[derive(
    Debug, Default, Copy, Clone, PartialEq, EnumFromStr, EnumTryFrom, EnumDisplay, FromNetwork,
)]
#[repr(u16)]
pub enum CertificateTypeValues {
    #[default]
    PKIX = 1, //X.509 as per PKIX
    SPKI = 2,    //SPKI certificate
    PGP = 3,     //OpenPGP packet
    IPKIX = 4,   //The URL of an X.509 data object
    ISPKI = 5,   //The URL of an SPKI certificate
    IPGP = 6,    //The fingerprint and URL of an OpenPGP packet
    ACPKIX = 7,  //Attribute Certificate
    IACPKIX = 8, //The URL of an Attribute Certificate
    URI = 253,   //URI private
    OID = 254,   //OID private
}

// https://www.rfc-editor.org/rfc/rfc4398.html#section-2
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             type              |             key tag           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   algorithm   |                                               /
// +---------------+            certificate or CRL                 /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
#[derive(Debug, Default, FromNetwork)]
pub struct CERT {
    // transmistted through RR deserialization
    #[deser(ignore)]
    pub(super) rd_length: u16,

    certificate_type: CertificateTypeValues,
    key_tag: u16,
    algorithm: u8,

    #[deser(with_code( self.certificate = Buffer::with_capacity(self.rd_length - 5); ))]
    certificate: Buffer,
}

// auto-implement new
new_rd_length!(CERT);

impl fmt::Display for CERT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.certificate_type,
            self.key_tag,
            self.algorithm,
            self.certificate.as_b64()
        )
    }
}

impl Serialize for CERT {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(4))?;
        seq.serialize_entry("flags", &self.certificate_type.to_string())?;
        seq.serialize_entry("key_tag", &self.key_tag)?;
        seq.serialize_entry("algorithm", &self.algorithm)?;
        seq.serialize_entry("certificate", &self.certificate.as_b64())?;
        seq.end()
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::{
//         error::DNSResult,
//         rfc::{rdata::RData, response::Response},
//         test_rdata,
//         tests::get_packets,
//     };

//     use type2network::FromNetworkOrder;

//     use super::CERT;

//     // test_rdata!(
//     //     rdata,
//     //     "./tests/cert.pcap",
//     //     true,
//     //     7,
//     //     RData::CERT,
//     //     (|x: &CERT, i: usize| {
//     //         match i {
//     //             0 => assert_eq!(x.to_string(), "PGP 0 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"),
//     //             1 => assert_eq!(x.to_string(), "0 issuewild \";\""),
//     //             2 => assert_eq!(x.to_string(), "0 iodef \"mailto:abuse@netmeister.org\""),
//     //             _ => panic!("data not is the pcap file"),
//     //         }
//     //     })
//     // );

//     // #[test]
//     // fn rdata() -> DNSResult<()> {
//     //     {
//     //         // extract response packet
//     //         let data = get_packets("./tests/cert.pcap", 0, 8);

//     //         // manage TCP length if any
//     //         let mut resp_buffer =
//     //             // DNS message starts at offset 0x44 when using TCP
//     //             std::io::Cursor::new(&data.1[..]);

//     //         println!("{:X?}", resp_buffer);

//     //         let mut resp = Response::default();
//     //         resp.deserialize_from(&mut resp_buffer)?;

//     //         let answer = resp.answer.unwrap();

//     //         for (i, a) in answer.iter().enumerate() {
//     //             if let RData::CERT(x) = &a.r_data {
//     //                 match i {
//     //                     0 => assert_eq!(x.to_string(), "PGP 0 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"),
//     //                     1 => assert_eq!(x.to_string(), "0 issuewild \";\""),
//     //                     2 => assert_eq!(x.to_string(), "0 iodef \"mailto:abuse@netmeister.org\""),
//     //                     _ => panic!("data not is the pcap file"),
//     //                 }
//     //                 //Ok(())
//     //             } else {
//     //                 panic!("RData not found in file {}", $file)
//     //             }
//     //         }

//     //         Ok(())
//     //     }
//     // }
// }
