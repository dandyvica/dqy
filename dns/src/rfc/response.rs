use std::{fmt, io::Cursor};

use log::{debug, trace};

use type2network::FromNetworkOrder;

use crate::{error::DNSResult, rfc::response_code::ResponseCode, transport::Transporter};

use super::{header::Header, question::Question, resource_record::RR};

#[derive(Default)]
pub struct Response<'a> {
    //pub(super) _length: Option<u16>, // length in case of TCP transport (https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2)
    pub header: Header,
    pub question: Question<'a>,
    pub(crate) answer: Option<Vec<RR<'a>>>,
    pub(super) authority: Option<Vec<RR<'a>>>,
    pub(super) additional: Option<Vec<RR<'a>>>,
}

// hide internal fields
impl<'a> Response<'a> {
    pub fn rcode(&self) -> ResponseCode {
        self.header.flags.response_code
    }

    pub fn ns_count(&self) -> u16 {
        self.header.ns_count
    }
}

impl<'a> Response<'a> {
    // Receive message for DNS resolver
    pub fn recv<T: Transporter>(&mut self, trp: &mut T, buffer: &'a mut [u8]) -> DNSResult<usize> {
        // receive packet from endpoint
        let received = trp.recv(buffer)?;
        debug!("received {} bytes", received);
        trace!("received buffer {:X?}", &buffer[..received]);

        // if using TCP, we get rid of 2 bytes which are the length of the message received
        // let mut cursor = if trp.uses_leading_length() {
        //     Cursor::new(&buffer[2..received])
        // } else {
        //     Cursor::new(&buffer[..received])
        // };
        let mut cursor = Cursor::new(&buffer[..received]);

        // get response
        self.deserialize_from(&mut cursor)?;
        trace!("response header: {}", self.header);
        trace!("response query: {}", self.question);
        trace!("response answer: {:?}", self.answer);
        trace!("response authority: {:?}", self.authority);

        Ok(received)
    }

    // pub fn display(&self) {
    //     // flags
    //     //println!("{}", self.header.flags);
    //     println!("HEADER: {}\n", self.header);
    //     println!("QUESTION: {}\n", self.question);

    //     // print out anwser, authority, additional if any
    //     if let Some(answer) = &self.answer {
    //         for a in answer {
    //             println!("{}", a);
    //         }
    //     }

    //     if let Some(auth) = &self.authority {
    //         for a in auth {
    //             println!("{}", a);
    //         }
    //     }

    //     if let Some(add) = &self.additional {
    //         for a in add {
    //             println!("{}", a);
    //         }
    //     }
    // }
}

impl<'a> fmt::Display for Response<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // print out anwser, authority, additional if any
        if let Some(answer) = &self.answer {
            for a in answer {
                writeln!(f, "{}", a)?;
            }
        }

        if let Some(auth) = &self.authority {
            for a in auth {
                writeln!(f, "{}", a)?;
            }
        }

        if let Some(add) = &self.additional {
            for a in add {
                writeln!(f, "{}", a)?;
            }
        }

        Ok(())
    }
}

impl<'a> FromNetworkOrder<'a> for Response<'a> {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        self.header.deserialize_from(buffer)?;
        trace!("deserialized header: {}", self.header);

        self.question.deserialize_from(buffer)?;
        trace!("deserialized question: {}", self.header);

        // for answer, additional, authorative, same process: allocate
        // vector to the number received
        if self.header.an_count > 0 {
            self.answer = Some(Vec::with_capacity(self.header.an_count as usize));
            self.answer.deserialize_from(buffer)?;
        }

        if self.header.ns_count > 0 {
            self.authority = Some(Vec::with_capacity(self.header.ns_count as usize));
            self.authority.deserialize_from(buffer)?;
        }

        if self.header.ar_count > 0 {
            self.additional = Some(Vec::with_capacity(self.header.ar_count as usize));
            self.additional.deserialize_from(buffer)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::{
        rfc::{
            a::A, opcode::OpCode, opt::opt::OptTTL, packet_type::PacketType, qclass::QClass,
            qtype::QType, rdata::RData, response_code::ResponseCode,
        },
        tests::get_packets,
    };

    use type2network::FromNetworkOrder;

    #[test]
    fn cap1() -> DNSResult<()> {
        let pcap = get_packets("./tests/cap1.pcap", 0, 1);
        let mut buffer = std::io::Cursor::new(&pcap.1[0x2A..]);

        let mut resp = Response::default();
        resp.deserialize_from(&mut buffer)?;

        assert_eq!(resp.header.flags.qr, PacketType::Response);
        assert_eq!(resp.header.flags.op_code, OpCode::Query);
        assert!(!resp.header.flags.authorative_answer);
        assert!(!resp.header.flags.truncation);
        assert!(resp.header.flags.recursion_desired);
        assert!(resp.header.flags.recursion_available);
        assert!(!resp.header.flags.z);
        assert!(!resp.header.flags.authentic_data);
        assert_eq!(resp.header.flags.response_code, ResponseCode::NoError);

        assert_eq!(resp.header.qd_count, 1);
        assert_eq!(resp.header.an_count, 1);
        assert_eq!(resp.header.ns_count, 0);
        assert_eq!(resp.header.ar_count, 0);

        assert_eq!(format!("{}", resp.question.qname), "www.google.com.");
        assert_eq!(resp.question.qtype, QType::A);
        assert_eq!(resp.question.qclass, QClass::IN);

        assert!(resp.answer.is_some());
        let answer = resp.answer.unwrap();
        assert_eq!(answer.len(), 1);

        let answer = &answer[0];
        assert_eq!(format!("{}", answer.name), "www.google.com.");
        assert_eq!(answer.r#type, QType::A);
        assert_eq!(answer.class.as_ref().unwrap_left(), &QClass::IN);
        assert_eq!(answer.ttl.as_ref().unwrap_left(), &119);
        assert_eq!(answer.rd_length, 4);

        assert!(
            matches!(answer.r_data, RData::A(A(addr)) if Ipv4Addr::from(addr) == Ipv4Addr::new(172,217,18,36))
        );

        Ok(())
    }

    #[test]
    fn cap2() -> DNSResult<()> {
        let pcap = get_packets("./tests/cap2.pcap", 0, 1);
        let mut buffer = std::io::Cursor::new(&pcap.1[0x2A..]);

        // check response
        let mut resp = Response::default();
        resp.deserialize_from(&mut buffer)?;

        assert_eq!(resp.header.flags.qr, PacketType::Response);
        assert_eq!(resp.header.flags.op_code, OpCode::Query);
        assert!(!resp.header.flags.authorative_answer);
        assert!(!resp.header.flags.truncation);
        assert!(resp.header.flags.recursion_desired);
        assert!(resp.header.flags.recursion_available);
        assert!(!resp.header.flags.z);
        assert!(resp.header.flags.authentic_data);
        assert_eq!(resp.header.flags.response_code, ResponseCode::NoError);

        assert_eq!(resp.header.qd_count, 1);
        assert_eq!(resp.header.an_count, 8);
        assert_eq!(resp.header.ns_count, 0);
        assert_eq!(resp.header.ar_count, 1);

        // check answers
        assert!(resp.answer.is_some());
        let answer = resp.answer.unwrap();
        assert_eq!(answer.len(), 8);

        for ans in &answer {
            assert_eq!(format!("{}", ans.name), "hk.");
            assert_eq!(ans.r#type, QType::NS);
            assert_eq!(ans.class.unwrap_left(), QClass::IN);
            //assert_eq!(ans.ttl.as_ref(), Left(&172800));
        }

        assert_eq!(answer[0].rd_length, 14);
        for i in 1..8 {
            assert_eq!(answer[i].rd_length, 4);
        }

        assert!(matches!(&answer[0].r_data, RData::NS(ns) if ns.to_string() == "c.hkirc.net.hk."));
        assert!(matches!(&answer[1].r_data, RData::NS(ns) if ns.to_string() == "d.hkirc.net.hk."));
        assert!(matches!(&answer[2].r_data, RData::NS(ns) if ns.to_string() == "t.hkirc.net.hk."));
        assert!(matches!(&answer[3].r_data, RData::NS(ns) if ns.to_string() == "u.hkirc.net.hk."));
        assert!(matches!(&answer[4].r_data, RData::NS(ns) if ns.to_string() == "v.hkirc.net.hk."));
        assert!(matches!(&answer[5].r_data, RData::NS(ns) if ns.to_string() == "x.hkirc.net.hk."));
        assert!(matches!(&answer[6].r_data, RData::NS(ns) if ns.to_string() == "y.hkirc.net.hk."));
        assert!(matches!(&answer[7].r_data, RData::NS(ns) if ns.to_string() == "z.hkirc.net.hk."));

        // check additional records
        assert!(resp.additional.is_some());
        let add = resp.additional.unwrap();
        assert_eq!(add.len(), 1);
        let add = &add[0];

        assert_eq!(format!("{}", add.name), ".");
        assert_eq!(add.r#type, QType::OPT);
        assert_eq!(add.class.unwrap_right(), 1232);
        assert_eq!(add.ttl.unwrap_right(), OptTTL::default());
        assert_eq!(add.rd_length, 0);

        Ok(())
    }
}
