use std::{fmt, io::Cursor, net::IpAddr};

use log::{debug, trace};
use serde::Serialize;
use type2network::FromNetworkOrder;

use super::{
    domain::DomainName, header::Header, qtype::QType, question::Question, resource_record::ResourceRecord,
    rrlist::RRList,
};
use crate::dns::rfc::response_code::ResponseCode;
use crate::error::{Dns, Error};
use crate::show::{DisplayOptions, Show};
use crate::transport::network::Messenger;

pub enum ResponseSection {
    Answer,
    Authority,
    Additional,
}

#[derive(Debug, Default, Serialize)]
pub struct Response {
    pub header: Header,
    pub question: Question,
    pub answer: Option<RRList>,
    pub(super) authority: Option<RRList>,
    pub(super) additional: Option<RRList>,
}

// hide internal fields
impl Response {
    #[inline]
    pub fn rcode(&self) -> ResponseCode {
        self.header.flags.response_code
    }

    #[inline]
    pub fn ns_count(&self) -> u16 {
        self.header.ns_count
    }

    #[inline]
    pub fn id(&self) -> u16 {
        self.header.id
    }

    #[inline]
    pub fn is_truncated(&self) -> bool {
        self.header.flags.bitflags.truncation
    }

    #[inline]
    pub fn is_authorative(&self) -> bool {
        self.header.flags.bitflags.authorative_answer
    }

    // referral response means no answer
    #[inline]
    pub fn is_referral(&self) -> bool {
        self.answer.is_none()
    }

    // return the max length of all RRs in either answer, additional or authority
    pub fn max_length(&self) -> usize {
        let m1 = if let Some(x) = &self.answer {
            x.max_length().unwrap_or(0)
        } else {
            0
        };
        let m2 = if let Some(x) = &self.authority {
            x.max_length().unwrap_or(0)
        } else {
            0
        };
        let m3 = if let Some(x) = &self.additional {
            x.max_length().unwrap_or(0)
        } else {
            0
        };

        usize::max(usize::max(m1, m2), m3)
    }

    // Receive message for DNS resolver
    pub fn recv<T: Messenger>(&mut self, trp: &mut T, buffer: &mut [u8]) -> crate::error::Result<usize> {
        // receive packet from endpoint
        let received = trp.recv(buffer)?;
        debug!("received {} bytes", received);
        trace!("received buffer {:X?}", &buffer[..received]);

        // if using TCP, we get rid of 2 bytes which are the length of the message received
        let mut cursor = Cursor::new(&buffer[..received]);

        // get response
        self.deserialize_from(&mut cursor)
            .map_err(|_| Error::Dns(Dns::CantDeserialize))?;
        trace!("response header: {}", self.header);
        trace!("response query: {}", self.question);
        trace!("response answer: {:?}", self.answer);
        trace!("response authority: {:?}", self.authority);

        Ok(received)
    }

    // return a random ip address in the glue records from the additional section
    pub fn random_glue_record(&self, qt: &QType) -> Option<&ResourceRecord> {
        if let Some(add) = &self.additional {
            // choose a random resource record for an A address
            let a_record = add.random(qt)?;
            Some(a_record)
        } else {
            None
        }
    }

    // return a random NS record in the answer section
    pub fn random_ns_record(&self) -> Option<&ResourceRecord> {
        if let Some(ans) = &self.authority {
            // choose a random resource record for an A address
            let ns_record = ans.random(&QType::NS)?;
            Some(ns_record)
        } else {
            None
        }
    }

    pub fn random_rr(&self, qt: &QType, cat: ResponseSection) -> Option<&ResourceRecord> {
        match cat {
            ResponseSection::Answer => {
                if let Some(ans) = &self.answer {
                    ans.random(qt)
                } else {
                    None
                }
            }
            ResponseSection::Authority => {
                if let Some(auth) = &self.authority {
                    auth.random(qt)
                } else {
                    None
                }
            }
            ResponseSection::Additional => {
                if let Some(add) = &self.additional {
                    add.random(qt)
                } else {
                    None
                }
            }
        }
    }

    // look for an ip address in anwer, additional and authority sections
    pub fn ip_address(&self, qt: &QType, name: &DomainName) -> Option<IpAddr> {
        if let Some(ans) = &self.answer {
            if let Some(ip) = ans.ip_address(qt, name) {
                return Some(ip);
            }
        }
        if let Some(add) = &self.additional {
            if let Some(ip) = add.ip_address(qt, name) {
                return Some(ip);
            }
        }
        if let Some(auth) = &self.authority {
            if let Some(ip) = auth.ip_address(qt, name) {
                return Some(ip);
            }
        }

        None
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // print out anwser, authority, additional if any
        if let Some(answer) = &self.answer {
            for a in answer.iter() {
                writeln!(f, "{}", a)?;
            }
        }

        if let Some(auth) = &self.authority {
            for a in auth.iter() {
                writeln!(f, "{}", a)?;
            }
        }

        if let Some(add) = &self.additional {
            for a in add.iter() {
                writeln!(f, "{}", a)?;
            }
        }

        Ok(())
    }
}

impl<'a> FromNetworkOrder<'a> for Response {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        self.header.deserialize_from(buffer)?;
        trace!("deserialized header: {}", self.header);

        self.question.deserialize_from(buffer)?;
        trace!("deserialized question: {}", self.header);

        // for answer, additional, authorative, same process: allocate
        // vector to the number received
        if self.header.an_count > 0 {
            // self.answer = Some(Vec::with_capacity(self.header.an_count as usize));
            self.answer = Some(RRList::with_capacity(self.header.an_count as usize));
            self.answer.deserialize_from(buffer)?;
        }

        if self.header.ns_count > 0 {
            self.authority = Some(RRList::with_capacity(self.header.ns_count as usize));
            self.authority.deserialize_from(buffer)?;
        }

        if self.header.ar_count > 0 {
            self.additional = Some(RRList::with_capacity(self.header.ar_count as usize));
            self.additional.deserialize_from(buffer)?;
        }

        Ok(())
    }
}

impl Show for Response {
    fn show(&self, display_options: &DisplayOptions, max_length: Option<usize>) {
        if self.header.an_count > 0 {
            debug_assert!(self.answer.is_some());

            if display_options.headers {
                println!("ANSWER:")
            }
            self.answer.as_ref().unwrap().show(display_options, max_length);
        }

        if self.header.ns_count > 0 && !display_options.no_authorative {
            debug_assert!(self.authority.is_some());

            if display_options.headers {
                println!("\nAUTHORATIVE:")
            }
            self.authority.as_ref().unwrap().show(display_options, max_length);
        }

        if self.header.ar_count > 0 && !display_options.no_additional {
            debug_assert!(self.additional.is_some());

            if display_options.headers {
                println!("\nADDITIONAL:")
            }
            self.additional.as_ref().unwrap().show(display_options, max_length);
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        dns::rfc::{
            opcode::OpCode, packet_type::PacketType, qclass::QClass, qtype::QType, rdata::RData,
            resource_record::OptOrClassTtl, response_code::ResponseCode,
        },
        dns::tests::get_packets,
    };

    use type2network::FromNetworkOrder;

    #[test]
    fn cap1() -> crate::error::Result<()> {
        let pcap = get_packets("./tests/pcap/cap1.pcap", 0, 1);
        let mut buffer = std::io::Cursor::new(&pcap.1[0x2A..]);

        let mut resp = Response::default();
        resp.deserialize_from(&mut buffer)
            .map_err(|_| Error::Dns(Dns::CantDeserialize))?;

        assert_eq!(resp.header.flags.qr, PacketType::Response);
        assert_eq!(resp.header.flags.op_code, OpCode::Query);
        assert!(!resp.header.flags.bitflags.authorative_answer);
        assert!(!resp.header.flags.bitflags.truncation);
        assert!(resp.header.flags.bitflags.recursion_desired);
        assert!(resp.header.flags.bitflags.recursion_available);
        assert!(!resp.header.flags.bitflags.z);
        assert!(!resp.header.flags.bitflags.authentic_data);
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
        assert!(matches!(&answer.opt_or_class_ttl, OptOrClassTtl::Regular(x) if x.class == QClass::IN));
        assert!(matches!(&answer.opt_or_class_ttl, OptOrClassTtl::Regular(x) if x.ttl == 119));
        assert_eq!(answer.rd_length, 4);

        // assert!(
        //     matches!(answer.r_data, RData::A(A(addr)) if Ipv4Addr::from(addr) == Ipv4Addr::new(172,217,18,36))
        // );

        Ok(())
    }

    #[test]
    fn cap2() -> crate::error::Result<()> {
        let pcap = get_packets("./tests/pcap/cap2.pcap", 0, 1);
        let mut buffer = std::io::Cursor::new(&pcap.1[0x2A..]);

        // check response
        let mut resp = Response::default();
        resp.deserialize_from(&mut buffer)
            .map_err(|_| Error::Dns(Dns::CantDeserialize))?;

        assert_eq!(resp.header.flags.qr, PacketType::Response);
        assert_eq!(resp.header.flags.op_code, OpCode::Query);
        assert!(!resp.header.flags.bitflags.authorative_answer);
        assert!(!resp.header.flags.bitflags.truncation);
        assert!(resp.header.flags.bitflags.recursion_desired);
        assert!(resp.header.flags.bitflags.recursion_available);
        assert!(!resp.header.flags.bitflags.z);
        assert!(resp.header.flags.bitflags.authentic_data);
        assert_eq!(resp.header.flags.response_code, ResponseCode::NoError);

        assert_eq!(resp.header.qd_count, 1);
        assert_eq!(resp.header.an_count, 8);
        assert_eq!(resp.header.ns_count, 0);
        assert_eq!(resp.header.ar_count, 1);

        // check answers
        assert!(resp.answer.is_some());
        let answer = resp.answer.unwrap();
        assert_eq!(answer.len(), 8);

        // for ans in answer.iter() {
        //     assert_eq!(format!("{}", ans.name), "hk.");
        //     assert_eq!(ans.r#type, QType::NS);
        //     assert_eq!(ans.class.unwrap_left(), QClass::IN);
        //     //assert_eq!(ans.ttl.as_ref(), Left(&172800));
        // }

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
        assert!(matches!(&add.opt_or_class_ttl, OptOrClassTtl::Opt(x) if x.payload == 1232));
        assert_eq!(add.rd_length, 0);

        Ok(())
    }
}
