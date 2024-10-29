use std::fmt;

// use log::trace;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use serde::Serialize;

use crate::{
    dns::buffer::{serialize_buffer, Buffer},
    new_rd_length,
};

use super::{nsec3param::NSEC3PARAM, type_bitmaps::TypeBitMaps};

//-------------------------------------------------------------------------------------
// NSEC3 depends on NSEC3PARAM
//-------------------------------------------------------------------------------------

// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Hash Alg.   |     Flags     |          Iterations           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Salt Length  |                     Salt                      /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Hash Length  |             Next Hashed Owner Name            /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                         Type Bit Maps                         /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, FromNetwork, Serialize)]
pub struct NSEC3 {
    // transmistted through RR deserialization
    #[serde(skip_serializing)]
    #[from_network(ignore)]
    pub(super) rd_length: u16,

    #[serde(flatten)]
    params: NSEC3PARAM,
    hash_length: u8,

    #[serde(serialize_with = "serialize_buffer")]
    #[from_network(with_code( self.owner_name = Buffer::with_capacity(self.hash_length); ))]
    owner_name: Buffer,

    #[from_network(with_code( self.types = TypeBitMaps::new(self.rd_length - (self.params.len() + 1 + self.hash_length as usize) as u16); ))]
    types: TypeBitMaps,
}

// auto-implement new
new_rd_length!(NSEC3);

impl fmt::Display for NSEC3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {:?} ", self.params, self.owner_name)?;

        for qt in &self.types.types {
            write!(f, "{} ", qt)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        dns::rfc::{rdata::RData, response::Response},
        dns::tests::get_packets,
    };

    use type2network::FromNetworkOrder;

    #[test]
    fn rdata() -> crate::error::Result<()> {
        {
            // extract response packet
            let data = get_packets("./tests/pcap/nsec3.pcap", 0, 1);

            // manage TCP length if any
            let mut resp_buffer = std::io::Cursor::new(&data.1[0x2A..]);

            println!("{:X?}", resp_buffer);

            let mut resp = Response::default();
            resp.deserialize_from(&mut resp_buffer)?;

            let answer = resp.authority.unwrap();

            for (i, a) in answer.iter().enumerate() {
                match i {
                    0 => {
                        if let RData::SOA(x) = &a.r_data {
                            assert_eq!(
                                &x.to_string(),
                                "panix.netmeister.org. jschauma.netmeister.org. 2021073555 3600 300 3600000 3600"
                            );
                        }
                    }
                    1 => {
                        if let RData::RRSIG(x) = &a.r_data {
                            assert_eq!(&x.to_string(), "SOA ECDSAP256SHA256 nsec3.dns.netmeister.org. 20240114141115 20231231131115 24381 5JizDTGokTMjAuzVYm27HH6STw70v8Hz8lS+QVHTpsxnQJhgCK2HjvSKtf/hnUgZKJ8ywNH9XTfBHK1oCrHxSQ==");
                        }
                    }
                    2 => {
                        if let RData::NSEC3(x) = &a.r_data {
                            assert_eq!(&x.to_string(), "1 0 15 508B7248F76E19FD AD409ACAD23C99B998D437318235167D65A06BDE NS SOA TXT RRSIG DNSKEY NSEC3PARAM CDS CDNSKEY ");
                        }
                    }
                    3 => {
                        if let RData::RRSIG(x) = &a.r_data {
                            assert_eq!(&x.to_string(), "NSEC3 ECDSAP256SHA256 nsec3.dns.netmeister.org. 20240109015350 20231226011049 24381 fTlRgL8n2BFwxMguZv1ASryNtCn9O9LhdsVqkZiPc8fTP8777QkHZsofNujVN93/+EcjqYPtfXibAyETUnC3jA==");
                        }
                    }
                    _ => panic!("unexpected pcap answer"),
                }
            }

            Ok(())
        }
    }
}
