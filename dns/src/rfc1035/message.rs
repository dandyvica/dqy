use std::fmt;
use std::io::Cursor;

use log::debug;
use rand::Rng;

use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::{ToNetwork, FromNetwork};

use crate::network::TransportType;
use crate::rfc1035::response_code::ResponseCode;
use crate::{
    error::DNSResult,
    network::Transport,
    rfc1035::{
        domain::DomainName, header::Header, opcode::OpCode, packet_type::PacketType,
        qclass::QClass, qtype::QType, question::Question, resource_record::ResourceRecord,
    },
};

// DNS packets are called "messages" in RFC1035:
// "All communications inside of the domain protocol are carried in a single format called a message"
// +---------------------+
// |        Header       |
// +---------------------+
// |       Question      | the question for the name server
// +---------------------+
// |        Answer       | RRs answering the question
// +---------------------+
// |      Authority      | RRs pointing toward an authority
// +---------------------+
// |      Additional     | RRs holding additional information
// +---------------------+
#[derive(Debug, Default, ToNetwork)]
pub struct Message<'a> {
    pub length: Option<u16>, // length in case of TCP transport (https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2)
    pub header: Header,
    pub question: Question<'a>,
    pub answer: Option<Vec<ResourceRecord<'a>>>,
    pub authority: Option<Vec<ResourceRecord<'a>>>,
    pub additional: Option<Vec<ResourceRecord<'a>>>,
}

impl<'a> Message<'a> {
    pub fn new(transport_type: &TransportType) -> Self {
        let mut msg = Self::default();

        if transport_type == &TransportType::Tcp {
            msg.length = Some(0u16);
        }

        msg
    }

    pub fn init(&mut self, domain: &'a str, qtype: QType, qclass: QClass) -> DNSResult<()> {
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
        self.question.qtype = qtype;
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
        if trp.is_tcp() {
            let bytes = (message_size - 2).to_be_bytes();
            buffer[0] = bytes[0];
            buffer[1] = bytes[1];
        };

        // send packet through the wire
        let sent = trp.send(&buffer)?;
        debug!("sent {} bytes", sent);

        Ok(sent)
    }

    // Receive message for DNS resolver
    pub fn recv(&mut self, trp: &mut Transport, buffer: &'a mut [u8]) -> DNSResult<usize> {
        // receive packet from endpoint
        let received = trp.recv(buffer)?;
        debug!("received {} bytes", received);

        // if using TCP, we get rid of 2 bytes which are the length of the message received
        let mut cursor = if trp.is_tcp() {
            Cursor::new(&buffer[2..received])
        } else {
            Cursor::new(&buffer[..received])
        };

        // get response
        self.deserialize_from(&mut cursor)?;

        // check return code
        if self.header.flags.response_code != ResponseCode::NoError {
            eprintln!("Response error!");
            std::process::exit(1);
        }

        Ok(received)
    }

    pub fn display(&self) {
        // header first
        println!("HEADER: {}\n", self.header);
        println!("QUESTION: {}\n", self.question);

        // print out anwser, authority, additional if any
        if let Some(answer) = &self.answer {
            for a in answer {
                println!("{}", a);
            }
        }

        if let Some(auth) = &self.authority {
            for a in auth {
                println!("{}", a);
            }
        }

        if let Some(add) = &self.additional {
            for a in add {
                println!("{}", a);
            }
        }
    }
}

impl<'a> fmt::Display for Message<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header)
    }
}

impl<'a> FromNetworkOrder<'a> for Message<'a> {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        self.header.deserialize_from(buffer)?;
        self.question.deserialize_from(buffer)?;

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