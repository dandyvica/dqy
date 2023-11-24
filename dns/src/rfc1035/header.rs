use std::fmt;

use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use super::{flags::Flags, packet_type::PacketType};

//  1  1  1  1  1  1
//  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
/// use std::io::Cursor;
/// use dns::rfc1035::{flags::Flags, header::Header};
/// use type2network::{FromNetworkOrder, ToNetworkOrder};
///
/// let sample = vec![0x49, 0x1e, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
/// let mut buffer = Cursor::new(sample.as_slice());
/// let mut h = Header::default();
/// assert!(h.deserialize_from(&mut buffer).is_ok());
/// assert_eq!(h.flags, Flags::try_from(0x0120).unwrap());
/// assert_eq!(h.qd_count, 1);
/// assert_eq!(h.an_count, 0);
/// assert_eq!(h.ns_count, 0);
/// assert_eq!(h.ar_count, 1);
///
/// let mut buffer: Vec<u8> = Vec::new();
/// assert!(h.serialize_to(&mut buffer).is_ok());
/// assert_eq!(buffer, sample);
/// ```
#[derive(Debug, Default, ToNetwork, FromNetwork)]
pub struct Header {
    pub id: u16, // A 16 bit identifier assigned by the program that
    // generates any kind of query.  This identifier is copied
    // the corresponding reply and can be used by the requester
    // to match up replies to outstanding queries.
    pub flags: Flags,
    pub qd_count: u16, // an unsigned 16 bit integer specifying the number of
    // entries in the question section.
    pub an_count: u16, // an unsigned 16 bit integer specifying the number of
    // resource records in the answer section.
    pub ns_count: u16, // an unsigned 16 bit integer specifying the number of name
    // server resource records in the authority records section.
    pub ar_count: u16, // an unsigned 16 bit integer specifying the number of
                       // resource records in the additional records section.
}

impl<'a> fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "id:0x{:X}({}) ", self.id, self.id)?;
        write!(f, "flags:<{}>  ", self.flags)?;

        if self.flags.qr == PacketType::Query {
            write!(f, "QUERY:{}", self.qd_count)
        } else {
            write!(
                f,
                "QUERY:{}, ANSWER:{} AUTHORITY:{} ADDITIONAL:{}",
                self.qd_count, self.an_count, self.ns_count, self.ar_count
            )
        }
    }
}
