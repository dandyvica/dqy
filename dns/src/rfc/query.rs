use std::{any::Any, fmt};

use log::{debug, trace};
use rand::Rng;

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use crate::{error::DNSResult, transport::Transporter};

use super::{
    domain::DomainName, header::Header, opcode::OpCode, opt::opt::OptQuery,
    packet_type::PacketType, qclass::QClass, qtype::QType, question::Question,
};

// a helper macro to define settings of flags
macro_rules! set_flag {
    // to deserialize "simple" structs (like A)
    ($func:ident, $field:ident) => {
        pub fn $func(&mut self, v: bool) {
            self.header.flags.$field = v;
        }
    };
}

#[derive(Default, ToNetwork)]
pub struct Query<'a> {
    pub length: Option<u16>, // length in case of TCP transport (https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2)
    pub header: Header,
    pub question: Question<'a>,
    pub additional: Option<Vec<Box<dyn ToNetworkOrder>>>,
}

impl<'a> Query<'a> {
    pub fn new<T: Transporter>(trp: &T) -> Self {
        let mut msg = Self::default();

        if trp.uses_leading_length() {
            msg.length = Some(0u16);
        }

        msg
    }

    pub fn push_additional<T: ToNetworkOrder + 'static>(&mut self, additional_rr: T) {
        if let Some(ref mut v) = self.additional {
            v.push(Box::new(additional_rr));
        } else {
            self.additional = Some(vec![Box::new(additional_rr)]);
        }
        self.header.ar_count += 1;
    }

    pub fn init(&mut self, domain: &'a str, qtype: &QType, qclass: QClass) -> DNSResult<()> {
        // fill header
        // create a random ID
        let mut rng = rand::thread_rng();
        self.header.id = rng.gen::<u16>();

        self.header.flags.qr = PacketType::Query;
        self.header.flags.op_code = OpCode::Query;
        //self.header.flags.recursion_desired = true;
        self.header.qd_count = 1;

        // fill question
        self.question.qname = DomainName::try_from(domain)?;
        self.question.qtype = *qtype;
        self.question.qclass = qclass;

        Ok(())
    }

    // Send the query through the wire
    pub fn send<T: Transporter>(&mut self, trp: &mut T) -> DNSResult<usize> {
        // convert to network bytes
        let mut buffer: Vec<u8> = Vec::new();
        let message_size = self.serialize_to(&mut buffer)? as u16;

        // if using TCP, we need to prepend the message sent with length of message
        if trp.uses_leading_length() {
            let bytes = (message_size - 2).to_be_bytes();
            buffer[0] = bytes[0];
            buffer[1] = bytes[1];
        };
        trace!("buffer to send: {:0X?}", buffer);

        // send packet through the wire
        trace!("query ==> {:#?}", self);
        let sent = trp.send(&buffer)?;
        debug!("sent {} bytes", sent);

        Ok(sent)
    }

    // define all set flags functions
    set_flag!(set_aa, authorative_answer);
    set_flag!(set_ad, authentic_data);
    set_flag!(set_cd, checking_disabled);
    set_flag!(set_ra, recursion_available);
    set_flag!(set_rd, recursion_desired);
    set_flag!(set_tc, truncation);

    pub fn display(&self) {
        // header first
        println!("HEADER: {}\n", self.header);
        println!("QUESTION: {}\n", self.question);
    }
}

impl<'a> fmt::Debug for Query<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "length:<{:?}> header:<{:?}> question:<{:?}>",
            self.length, self.header, self.question
        )?;

        if let Some(add) = &self.additional {
            for rr in add {
                debug_rr(rr, f)?;
            }
        }

        Ok(())
    }
}

fn debug_rr<T: Any>(value: &T, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let value_any = value as &dyn Any;
    // println!(
    //     "=> {:?}",
    //     value_any.downcast_ref::<ResourceRecord<'_, Vec<OptOption>>>()
    // );
    if let Some(rr) = value_any.downcast_ref::<OptQuery>() {
        write!(f, "OPT: <{:?}>", rr)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{rfc::response_code::ResponseCode, tests::get_packets};

    use type2network::FromNetworkOrder;

    #[test]
    fn cap1() -> DNSResult<()> {
        let pcap = get_packets("./tests/cap1.pcap", 0, 1);
        let mut buffer = std::io::Cursor::new(&pcap.0[0x2A..]);

        // check query
        let mut query = Query::default();
        query.header.deserialize_from(&mut buffer)?;

        assert_eq!(query.header.flags.qr, PacketType::Query);
        assert_eq!(query.header.flags.op_code, OpCode::Query);
        assert!(!query.header.flags.authorative_answer);
        assert!(!query.header.flags.truncation);
        assert!(query.header.flags.recursion_desired);
        assert!(!query.header.flags.recursion_available);
        assert!(!query.header.flags.z);
        assert!(query.header.flags.authentic_data);
        assert_eq!(query.header.flags.response_code, ResponseCode::NoError);

        assert_eq!(query.header.qd_count, 1);
        assert_eq!(query.header.an_count, 0);
        assert_eq!(query.header.ns_count, 0);
        assert_eq!(query.header.ar_count, 0);

        query.question.deserialize_from(&mut buffer)?;
        assert_eq!(format!("{}", query.question.qname), "www.google.com.");
        assert_eq!(query.question.qtype, QType::A);
        assert_eq!(query.question.qclass, QClass::IN);

        Ok(())
    }

    #[test]
    fn cap2() -> DNSResult<()> {
        let pcap = get_packets("./tests/cap2.pcap", 0, 1);
        let mut buffer = std::io::Cursor::new(&pcap.0[0x2A..]);

        // check query
        let mut query = Query::default();
        query.header.deserialize_from(&mut buffer)?;

        assert_eq!(query.header.flags.qr, PacketType::Query);
        assert_eq!(query.header.flags.op_code, OpCode::Query);
        assert!(!query.header.flags.authorative_answer);
        assert!(!query.header.flags.truncation);
        assert!(query.header.flags.recursion_desired);
        assert!(!query.header.flags.recursion_available);
        assert!(!query.header.flags.z);
        assert!(query.header.flags.authentic_data);
        assert_eq!(query.header.flags.response_code, ResponseCode::NoError);

        assert_eq!(query.header.qd_count, 1);
        assert_eq!(query.header.an_count, 0);
        assert_eq!(query.header.ns_count, 0);
        assert_eq!(query.header.ar_count, 1);

        query.question.deserialize_from(&mut buffer)?;
        assert_eq!(format!("{}", query.question.qname), "hk.");
        assert_eq!(query.question.qtype, QType::NS);
        assert_eq!(query.question.qclass, QClass::IN);

        // query.additional.deserialize_from(&mut buffer.buf_query)?;
        // assert!(query.additional.is_some());
        // let add = query.additional.unwrap();
        // assert_eq!(add.len(), 1);
        // let add = &add[0];

        // assert_eq!(format!("{}", add.name), ".");
        // assert_eq!(add.r#type, QType::OPT);
        // assert!(matches!(add.class, Class::Payload(pl) if pl == 1232));
        // assert_eq!(add.ttl, 0);
        // assert_eq!(add.rd_length, 12);

        // if let RData::Opt(opt) = add.r_data.as_ref().unwrap() {
        //     assert_eq!(opt.option_code, OptionCode::COOKIE);
        //     assert_eq!(opt.option_length, 8);
        //     assert!(
        //         matches!(&opt.option_data, OptionData::Cookie(cookie) if cookie.client_cookie == [0x9a, 0xe7, 0x01, 0xa1, 0x3b, 0x61, 0x57, 0x2e])
        //     );
        // }

        Ok(())
    }
}
