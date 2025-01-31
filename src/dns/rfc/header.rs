use std::fmt;

use colored::Colorize;
use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{FromNetwork, ToNetwork};

use rand::Rng;
use serde::Serialize;

use super::{flags::Flags, opcode::OpCode, packet_type::PacketType, response_code::ResponseCode};

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
#[derive(Debug, Clone, ToNetwork, FromNetwork, Serialize)]
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

impl Header {
    // DoQ must set ID to 0: https://datatracker.ietf.org/doc/rfc9250/ section 4.2.1
    pub fn set_id(&mut self, id: u16) {
        self.id = id;
    }

    pub fn set_response_code(&mut self, rc: ResponseCode) {
        self.flags.set_response_code(rc);
    }    
}

impl Default for Header {
    fn default() -> Self {
        // by default, we use the recursion desired flag at query
        let flags = Flags {
            qr: PacketType::Query,
            op_code: OpCode::Query,
            ..Default::default()
        };

        let mut rng = rand::thread_rng();

        Self {
            id: rng.gen::<u16>(),
            flags,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:0x{:X}({}) ", "id".bright_cyan(), self.id, self.id)?;
        write!(f, "{}:<{}>  ", "flags".bright_cyan(), self.flags)?;

        if self.flags.qr == PacketType::Query {
            write!(f, "{}:{}", "qd_count".bright_cyan(), self.qd_count)
        } else {
            write!(
                f,
                "qd_count:{}, an_count:{} ns_count:{} ar_count:{}",
                self.qd_count, self.an_count, self.ns_count, self.ar_count
            )
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn network() {
        use crate::dns::rfc::header::Header;
        use std::io::Cursor;
        use type2network::{FromNetworkOrder, ToNetworkOrder};

        let sample = vec![0x49, 0x1e, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut buffer = Cursor::new(sample.as_slice());
        let mut h = Header::default();
        assert!(h.deserialize_from(&mut buffer).is_ok());
        //assert_eq!(h.flags, Flags::try_from(0x0120).unwrap());
        assert_eq!(h.qd_count, 1);
        assert_eq!(h.an_count, 0);
        assert_eq!(h.ns_count, 0);
        assert_eq!(h.ar_count, 1);

        let mut buffer: Vec<u8> = Vec::new();
        assert!(h.serialize_to(&mut buffer).is_ok());
        assert_eq!(buffer, sample);
    }
}
