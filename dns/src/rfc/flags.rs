use std::fmt;
use std::io::{Cursor, Result};

use crate::{
    error::{Error, ProtocolError},
    //getter,
    rfc::{opcode::OpCode, response_code::ResponseCode},
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use type2network::{FromNetworkOrder, ToNetworkOrder};

use super::packet_type::PacketType;

// Flags: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
// 1  1  1  1  1  1
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug, Default, PartialEq)]
pub struct Flags {
    pub(super) qr: PacketType, // A one bit field that specifies whether this message is a query (0), or a response (1).
    pub(super) op_code: OpCode, // A four bit field that specifies kind of query in this
    //  message.  This value is set by the originator of a query
    //  and copied into the response.  The values are:
    // 0               a standard query (QUERY)
    // 1               an inverse query (IQUERY)
    // 2               a server status request (STATUS)
    // 3-15            reserved for future use
    pub(super) authorative_answer: bool, // Authoritative Answer - this bit is valid in responses,
    //and specifies that the responding name server is an
    //authority for the domain name in question section.
    //Note that the contents of the answer section may have
    //multiple owner names because of aliases.  The AA bit
    //corresponds to the name which matches the query name, or
    //the first owner name in the answer section.
    pub truncated: bool, //    TrunCation - specifies that this message was truncated
    //    due to length greater than that permitted on the
    //    transmission channel.
    pub(super) recursion_desired: bool, // Recursion Desired - this bit may be set in a query and
    // is copied into the response.  If RD is set, it directs
    // the name server to pursue the query recursively.
    // Recursive query support is optional.
    pub(super) recursion_available: bool, // Recursion Available - this be is set or cleared in a
    //  response, and denotes whether recursive query support is
    //  available in the name server.
    pub(super) z: bool, // Reserved for future use.  Must be zero in all queries and responses.
    pub(super) authentic_data: bool,
    pub(super) checking_disabled: bool,
    pub(super) response_code: ResponseCode, // Response code - this 4 bit field is set as part of
                                            //responses.  The values have the following
                                            //interpretation:
                                            //0               No error condition
                                            //1               Format error - The name server was
                                            //                unable to interpret the query.
                                            //2               Server failure - The name server was
                                            //                unable to process this query due to a
                                            //                problem with the name server.
                                            //3               Name Error - Meaningful only for
                                            //                responses from an authoritative name
                                            //                server, this code signifies that the
                                            //                domain name referenced in the query does
                                            //                not exist.
                                            //4               Not Implemented - The name server does
                                            //                not support the requested kind of query.
                                            //5               Refused - The name server refuses to
                                            //                perform the specified operation for
                                            //                policy reasons.  For example, a name
                                            //                server may not wish to provide the
                                            //                information to the particular requester,
                                            //                or a name server may not wish to perform
                                            //                a particular operation (e.g., zone
                                            //                transfer) for particular data.
                                            //6-15            Reserved for future use.
}

//getter!(Flags, qr, PacketType);

impl TryFrom<u16> for Flags {
    type Error = Error;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        let mut flags = Self::default();

        // check for packet_type inconsistencies
        let qr = (value >> 15) as u8;
        debug_assert!(
            qr == 0_u8 || qr == 1,
            "QR is neither a question nor a response, value = {}",
            qr
        );

        flags.qr = PacketType::try_from(qr)
            .map_err(|_| Error::InternalError(ProtocolError::UnknowPacketType))?;

        flags.op_code = OpCode::try_from((value >> 11 & 0b1111) as u8)
            .map_err(|_| Error::InternalError(ProtocolError::UnknowOpCode))?;

        flags.authorative_answer = (value >> 10) & 1 == 1;
        flags.truncated = (value >> 9) & 1 == 1;
        flags.recursion_desired = (value >> 8) & 1 == 1;
        flags.recursion_available = (value >> 7) & 1 == 1;
        flags.z = (value >> 6 & 1) == 1;
        flags.authentic_data = (value >> 5 & 1) == 1;
        flags.checking_disabled = (value >> 4 & 1) == 1;
        flags.response_code = ResponseCode::try_from((value & 0b1111) as u8)
            .map_err(|_| Error::InternalError(ProtocolError::UnknowOpCode))?;

        Ok(flags)
    }
}

impl ToNetworkOrder for Flags {
    fn serialize_to(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        // combine all flags according to structure
        //                                1  1  1  1  1  1
        //  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      ID                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        let mut flags = (self.qr as u16) << 15;
        flags |= (self.op_code as u16) << 11;
        flags |= (self.authorative_answer as u16) << 10;
        flags |= (self.truncated as u16) << 9;
        flags |= (self.recursion_desired as u16) << 8;
        flags |= (self.recursion_available as u16) << 7;
        flags |= (self.z as u16) << 6;
        flags |= (self.authentic_data as u16) << 5;
        flags |= (self.checking_disabled as u16) << 4;
        flags |= self.response_code as u16;

        buffer.write_u16::<BigEndian>(flags)?;
        Ok(2)
    }
}

impl<'a> FromNetworkOrder<'a> for Flags {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&[u8]>) -> Result<()> {
        // read as u16
        let flags = buffer.read_u16::<BigEndian>()?;
        *self = Flags::try_from(flags).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "error converting flags")
        })?;

        Ok(())
    }
}

// helper macro to print out boolean flags if true
macro_rules! flag_display {
    ($fmt:expr, $bit:expr, $label:literal) => {
        if $bit {
            write!($fmt, "{} ", $label)?
        }
    };
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // output depends on whether it's a query or a response
        // because some fields are unnecessary when Query or Response
        write!(f, "qr:{:?} ", self.qr)?;

        if self.qr == PacketType::Query {
            write!(f, "opcode:{:?} rd:{}", self.op_code, self.recursion_desired)
        } else {
            write!(f, "code:{} ", self.response_code)?;

            flag_display!(f, self.authorative_answer, "aa");
            flag_display!(f, self.truncated, "tc");
            flag_display!(f, self.recursion_desired, "rd");
            flag_display!(f, self.recursion_available, "ra");
            flag_display!(f, self.authentic_data, "ad");
            flag_display!(f, self.checking_disabled, "cd");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rfc::{
        flags::Flags, opcode::OpCode, packet_type::PacketType, response_code::ResponseCode,
    };

    #[test]
    fn try_from() {
        use std::convert::TryFrom;

        let x = 0b_1000_1111_1111_0001;
        let v = Flags::try_from(x).unwrap();
        assert_eq!(v.qr, PacketType::Response);
        assert_eq!(v.op_code, OpCode::IQuery);
        assert!(v.authorative_answer);
        assert!(v.truncated);
        assert!(v.recursion_desired);
        assert!(v.recursion_available);
        assert!(v.z);
        assert!(v.authentic_data);
        assert!(v.checking_disabled);
        assert_eq!(v.response_code, ResponseCode::FormErr);
    }

    #[test]
    fn serialize_to() {
        use type2network::ToNetworkOrder;

        let flags = Flags {
            qr: PacketType::Response,
            op_code: OpCode::IQuery,
            authorative_answer: true,
            truncated: true,
            recursion_desired: true,
            recursion_available: true,
            z: true,
            authentic_data: true,
            checking_disabled: true,
            response_code: ResponseCode::NoError,
        };

        let mut buffer: Vec<u8> = Vec::new();
        assert!(flags.serialize_to(&mut buffer).is_ok());
        assert_eq!(buffer, &[0b1000_1111, 0b1111_0000]);
    }

    #[test]
    fn deserialize_from() {
        use std::io::Cursor;
        use type2network::FromNetworkOrder;

        let b = vec![0b_10001111, 0b_1111_0001];
        let mut buffer = Cursor::new(b.as_slice());
        let mut v = Flags::default();
        assert!(v.deserialize_from(&mut buffer).is_ok());
        assert_eq!(v.qr, PacketType::Response);
        assert_eq!(v.op_code, OpCode::IQuery);
        assert!(v.authorative_answer);
        assert!(v.truncated);
        assert!(v.recursion_desired);
        assert!(v.recursion_available);
        assert!(v.z);
        assert!(v.authentic_data);
        assert!(v.checking_disabled);
        assert_eq!(v.response_code, ResponseCode::FormErr);
    }
}
