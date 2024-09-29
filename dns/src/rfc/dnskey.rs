use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{buffer::Buffer, new_rd_length};

use super::algorithm::DNSSECAlgorithmTypes;

// https://www.rfc-editor.org/rfc/rfc4034.html
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Flags            |    Protocol   |   Algorithm   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                            Public Key                         /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, FromNetwork)]
pub(super) struct DNSKEY {
    #[from_network(ignore)]
    rd_length: u16,

    // Bit 7 of the Flags field is the Zone Key flag.  If bit 7 has value 1,
    // then the DNSKEY record holds a DNS zone key, and the DNSKEY RR's
    // owner name MUST be the name of a zone.  If bit 7 has value 0, then
    // the DNSKEY record holds some other type of DNS public key and MUST
    // NOT be used to verify RRSIGs that cover RRsets.
    //
    // Bit 15 of the Flags field is the Secure Entry Point flag, described
    // in [RFC3757].  If bit 15 has value 1, then the DNSKEY record holds a
    // key intended for use as a secure entry point.  This flag is only
    // intended to be a hint to zone signing or debugging software as to the
    // intended use of this DNSKEY record; validators MUST NOT alter their
    // behavior during the signature validation process in any way based on
    // the setting of this bit.  This also means that a DNSKEY RR with the
    // SEP bit set would also need the Zone Key flag set in order to be able
    // to generate signatures legally.  A DNSKEY RR with the SEP set and the
    // Zone Key flag not set MUST NOT be used to verify RRSIGs that cover
    // RRsets.
    //
    // Bits 0-6 and 8-14 are reserved: these bits MUST have value 0 upon
    // creation of the DNSKEY RR and MUST be ignored upon receipt.
    //
    // The Flag field MUST be represented as an unsigned decimal integer.
    // Given the currently defined flags, the possible values are: 0, 256,
    // and 257.
    flags: u16,

    // The Protocol Field MUST have value 3, and the DNSKEY RR MUST be
    // treated as invalid during signature verification if it is found to be
    // some value other than 3.
    protocol: u8,

    // The Algorithm field identifies the public key's cryptographic
    // algorithm and determines the format of the Public Key field.  A list
    // of DNSSEC algorithm types can be found in Appendix A.1
    algorithm: DNSSECAlgorithmTypes,

    // The Public Key Field holds the public key material.  The format
    // depends on the algorithm of the key being stored and is described in
    // separate documents.
    #[from_network(with_code( self.key = Buffer::with_capacity(self.rd_length - 4); ))]
    key: Buffer,
}

// auto-implement new
new_rd_length!(DNSKEY);

impl fmt::Display for DNSKEY {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.flags,
            self.protocol,
            self.algorithm,
            self.key.to_b64()
        )
    }
}

#[allow(clippy::upper_case_acronyms)]
pub(super) type CDNSKEY = DNSKEY;

// Custom serialization
use serde::{ser::SerializeMap, Serialize, Serializer};
impl Serialize for DNSKEY {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(4))?;
        seq.serialize_entry("flags", &self.flags)?;
        seq.serialize_entry("protocol", &self.protocol)?;
        seq.serialize_entry("algorithm", &self.algorithm.to_string())?;
        seq.serialize_entry("key", &self.key.to_b64())?;
        seq.end()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        rfc::{rdata::RData, response::Response},
        test_rdata,
        tests::get_packets,
    };

    use type2network::FromNetworkOrder;

    use super::DNSKEY;

    test_rdata!(
        rdata_dnskey,
        "./tests/dnskey.pcap",
        false,
        1,
        RData::DNSKEY,
        (|x: &DNSKEY, _| {
            assert_eq!(&x.to_string(), "257 3 ECDSAP256SHA256 XEn4q8CbG2a4Hw47Ih244BDkwY1tOuprXWKEzMyLPtjO9iIRVt4HLLbx9YaeaYzRcH91mvCstP8I5liQ0Mn1bA==");
        })
    );

    test_rdata!(
        rdata_cdnskey,
        "./tests/cdnskey.pcap",
        false,
        1,
        RData::CDNSKEY,
        (|x: &DNSKEY, _| {
            assert_eq!(&x.to_string(), "257 3 ECDSAP256SHA256 JErBf5lZ1osSWg7r51+4VfEiWIdONph0L70X0ToT7DkbikKQIp+qvuOOZri7j3qVComv7tgTIBhKxeDQercdKQ==");
        })
    );
}
