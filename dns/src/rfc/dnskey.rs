use std::fmt;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use base64::{engine::general_purpose, Engine as _};

use crate::buffer::Buffer;

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
pub struct DNSKEY {
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
    pub flags: u16,

    // The Protocol Field MUST have value 3, and the DNSKEY RR MUST be
    // treated as invalid during signature verification if it is found to be
    // some value other than 3.
    pub protocol: u8,

    // The Algorithm field identifies the public key's cryptographic
    // algorithm and determines the format of the Public Key field.  A list
    // of DNSSEC algorithm types can be found in Appendix A.1
    pub algorithm: u8,

    // The Public Key Field holds the public key material.  The format
    // depends on the algorithm of the key being stored and is described in
    // separate documents.
    //#[deser(with_code( self.key = Buffer::new(self.rd_length - 4); ))]
    pub key: Buffer,
}

impl fmt::Display for DNSKEY {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "flags:{} protocol:{} algorithm:{} key:",
            self.flags, self.protocol, self.algorithm
        )?;

        let b64 = general_purpose::STANDARD.encode(&self.key);
        write!(f, "{}", b64)?;

        Ok(())
    }
}
