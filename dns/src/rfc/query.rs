use log::debug;
use rand::Rng;

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use crate::{
    error::DNSResult,
    network::transport::{Transport, TransportMode},
};

use super::{
    domain::DomainName, header::Header, opcode::OpCode, packet_type::PacketType, qclass::QClass,
    qtype::QType, question::Question,
};

#[derive(Default, ToNetwork)]
pub struct Query<'a> {
    pub length: Option<u16>, // length in case of TCP transport (https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2)
    pub header: Header,
    pub question: Question<'a>,
    pub additional: Option<Vec<Box<dyn ToNetworkOrder>>>,
}

impl<'a> Query<'a> {
    pub fn new(transport_mode: &TransportMode) -> Self {
        let mut msg = Self::default();

        if transport_mode.uses_tcp() {
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
        self.header.flags.recursion_desired = true;
        self.header.qd_count = 1;

        // fill question
        self.question.qname = DomainName::try_from(domain)?;
        self.question.qtype = *qtype;
        self.question.qclass = qclass;

        // OPT?
        // if opt.is_some() {
        //     self.opt = opt;
        // }

        Ok(())
    }

    // Send the query through the wire
    pub fn send(&self, trp: &mut Transport) -> DNSResult<usize> {
        // convert to network bytes
        let mut buffer: Vec<u8> = Vec::new();
        let message_size = self.serialize_to(&mut buffer)? as u16;

        // if using TCP, we need to prepend the message sent with length of message
        if trp.uses_tcp() {
            let bytes = (message_size - 2).to_be_bytes();
            buffer[0] = bytes[0];
            buffer[1] = bytes[1];
        };

        // send packet through the wire
        let sent = trp.send(&buffer)?;
        debug!("sent {} bytes", sent);

        Ok(sent)
    }

    pub fn display(&self) {
        // header first
        println!("HEADER: {}\n", self.header);
        println!("QUESTION: {}\n", self.question);
    }
}
