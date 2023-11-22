use std::io::Cursor;

use log::debug;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use crate::{
    error::DNSResult,
    network::{Transport, TransportType},
    rfc1035::response_code::ResponseCode,
};

use super::{header::Header, question::Question, resource_record::RR};

#[derive(Default)]
pub struct Response<'a> {
    pub length: Option<u16>, // length in case of TCP transport (https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2)
    pub header: Header,
    pub question: Question<'a>,
    pub answer: Option<Vec<RR<'a>>>,
    pub authority: Option<Vec<RR<'a>>>,
    pub additional: Option<Vec<RR<'a>>>,
}

impl<'a> Response<'a> {
    pub fn new(transport_type: &TransportType) -> Self {
        let mut msg = Self::default();

        if transport_type == &TransportType::Tcp {
            msg.length = Some(0u16);
        }

        msg
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

impl<'a> FromNetworkOrder<'a> for Response<'a> {
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
