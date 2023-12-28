use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use base64::{engine::general_purpose, Engine as _};

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
#[derive(Debug, Default, FromNetwork)]
pub(super) struct DNSKEY {
    #[deser(ignore)]
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
    #[deser(with_code( self.key = Buffer::new(self.rd_length - 4); ))]
    key: Buffer,
}

// auto-implement new
new_rd_length!(DNSKEY);

impl fmt::Display for DNSKEY {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} ", self.flags, self.protocol, self.algorithm)?;

        let b64 = general_purpose::STANDARD.encode(&self.key);
        write!(f, "{}", b64)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::DNSResult,
        rfc::{rdata::RData, response::Response},
        test_rdata,
        tests::{get_pcap_buffer, read_pcap_sample},
    };

    use type2network::FromNetworkOrder;

    use super::DNSKEY;

    test_rdata!(
        "./tests/dnskey.pcap",
        RData::DNSKEY,
        (|x: &DNSKEY, _| {
            assert_eq!(&x.to_string(), "257 3 ECDSAP256SHA256 XEn4q8CbG2a4Hw47Ih244BDkwY1tOuprXWKEzMyLPtjO9iIRVt4HLLbx9YaeaYzRcH91mvCstP8I5liQ0Mn1bA==");
        })
    );
}
