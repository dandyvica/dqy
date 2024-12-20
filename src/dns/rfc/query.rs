use std::fmt;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use log::{debug, trace};
use serde::Serialize;
use tokio::io::AsyncWriteExt;

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use crate::error::{Dns, Error, Result};
use crate::transport::network::Messenger;

use super::{
    domain::DomainName, flags::BitFlags, header::Header, qclass::QClass, qtype::QType, question::Question,
    resource_record::OPT,
};

#[derive(Debug, ToNetwork, Serialize)]
pub enum MetaRR {
    OPT(OPT),
}

impl Default for MetaRR {
    fn default() -> Self {
        // https://datatracker.ietf.org/doc/html/rfc6891#section-6.2.5
        // RFC recommends 4096 bytes to start with
        Self::OPT(OPT::new(4096, None))
    }
}

#[derive(Debug, Default, ToNetwork, Serialize)]
pub struct Query {
    #[serde(skip_serializing)]
    pub length: Option<u16>, // length in case of TCP/TLS transport (https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2)
    pub header: Header,
    pub question: Question,
    pub additional: Option<Vec<MetaRR>>,
}

impl Query {
    //───────────────────────────────────────────────────────────────────────────────────
    // builder pattern for adding lots of options to a query
    //───────────────────────────────────────────────────────────────────────────────────
    pub fn build() -> Self {
        Self {
            header: Header::default(),
            ..Default::default()
        }
    }

    pub fn with_type(mut self, qt: &QType) -> Self {
        self.question.qtype = *qt;
        self
    }

    pub fn with_class(mut self, qc: &QClass) -> Self {
        self.question.qclass = *qc;
        self
    }

    pub fn with_domain(mut self, domain: &DomainName) -> Self {
        self.question.qname = domain.clone();
        self
    }

    pub fn with_flags(mut self, flags: &BitFlags) -> Self {
        self.header.flags.bitflags = flags.clone();
        self
    }

    pub fn with_additional(mut self, additional_rr: MetaRR) -> Self {
        if let Some(ref mut v) = self.additional {
            v.push(additional_rr);
        } else {
            self.additional = Some(vec![additional_rr]);
        }
        self.header.ar_count += 1;
        self
    }

    pub fn with_length(mut self) -> Self {
        trace!("==============> inside with_length");
        self.length = Some(0u16);
        self
    }

    // Send the query through the wire
    pub fn send<T: Messenger>(&mut self, trp: &mut T, save_path: &Option<PathBuf>) -> Result<usize> {
        // convert to network bytes
        let mut buffer: Vec<u8> = Vec::new();
        let message_size = self
            .serialize_to(&mut buffer)
            .map_err(|_| Error::Dns(Dns::CantSerialize))? as u16;
        trace!(
            "buffer to send before TCP length addition: {:0X?}, uses_leading_length={}",
            buffer,
            trp.uses_leading_length()
        );

        // if using TCP, we need to prepend the message sent with length of message
        if trp.uses_leading_length() {
            let bytes = (message_size - 2).to_be_bytes();
            buffer[..2].copy_from_slice(&bytes);

            // not really necessary but to be aligned with what is sent
            self.length = Some(message_size);
        };
        trace!("buffer to send: {:0X?}", buffer);

        // send packet through the wire
        let sent = trp.send(&buffer)?;
        debug!("sent {} bytes", sent);

        // save query as raw bytes if requested
        if let Some(path) = save_path {
            let mut f = File::create(path).map_err(|e| Error::OpenFile(e, path.to_path_buf()))?;
            f.write_all(&buffer).map_err(Error::Buffer)?;
        }

        Ok(sent)
    }

    // Send the query through the wire, async version
    pub async fn asend<T: Messenger>(&mut self, trp: &mut T, save_path: &Option<PathBuf>) -> Result<usize> {
        // convert to network bytes
        let mut buffer: Vec<u8> = Vec::new();
        let message_size = self
            .serialize_to(&mut buffer)
            .map_err(|_| Error::Dns(Dns::CantSerialize))? as u16;
        trace!(
            "buffer to send before TCP length addition: {:0X?}, uses_leading_length={}",
            buffer,
            trp.uses_leading_length()
        );

        // if using TCP, we need to prepend the message sent with length of message
        if trp.uses_leading_length() {
            let bytes = (message_size - 2).to_be_bytes();
            buffer[..2].copy_from_slice(&bytes);

            // not really necessary but to be aligned with what is sent
            self.length = Some(message_size);
        };
        trace!("buffer to send: {:0X?}", buffer);

        // send packet through the wire
        let sent = trp.asend(&buffer).await?;
        debug!("sent {} bytes", sent);

        // save query as raw bytes if requested
        if let Some(path) = save_path {
            let mut f = tokio::fs::File::create(path)
                .await
                .map_err(|e| Error::OpenFile(e, path.to_path_buf()))?;
            f.write_all(&buffer).await.map_err(Error::Buffer)?;
        }

        Ok(sent)
    }

    pub fn display(&self) {
        // header first
        println!("HEADER: {}\n", self.header);
        println!("QUESTION: {}\n", self.question);
    }
}

// impl fmt::Debug for Query {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(
//             f,
//             "length:<{:?}> header:<{:?}> question:<{:?}>",
//             self.length, self.header, self.question
//         )?;

//         if let Some(add) = &self.additional {
//             for rr in add {
//                 write!(f, "{:?}", rr)?;
//             }
//         }

//         Ok(())
//     }
// }

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header)?;
        write!(f, "{}", self.question)?;
        write!(f, "{:?}", self.additional)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dns::rfc::{opcode::OpCode, packet_type::PacketType, response_code::ResponseCode},
        dns::tests::get_packets,
        error::{Dns, Error},
    };

    use type2network::FromNetworkOrder;

    #[test]
    fn cap1() -> Result<()> {
        let pcap = get_packets("./tests/pcap/cap1.pcap", 0, 1);
        let mut buffer = std::io::Cursor::new(&pcap.0[0x2A..]);

        // check query
        let mut query = Query::default();
        query
            .header
            .deserialize_from(&mut buffer)
            .map_err(|_| Error::Dns(Dns::CantDeserialize))?;

        assert_eq!(query.header.flags.qr, PacketType::Query);
        assert_eq!(query.header.flags.op_code, OpCode::Query);
        assert!(!query.header.flags.bitflags.authorative_answer);
        assert!(!query.header.flags.bitflags.truncation);
        assert!(query.header.flags.bitflags.recursion_desired);
        assert!(!query.header.flags.bitflags.recursion_available);
        assert!(!query.header.flags.bitflags.z);
        assert!(query.header.flags.bitflags.authentic_data);
        assert_eq!(query.header.flags.response_code, ResponseCode::NoError);

        assert_eq!(query.header.qd_count, 1);
        assert_eq!(query.header.an_count, 0);
        assert_eq!(query.header.ns_count, 0);
        assert_eq!(query.header.ar_count, 0);

        query
            .question
            .deserialize_from(&mut buffer)
            .map_err(|_| Error::Dns(Dns::CantDeserialize))?;
        assert_eq!(format!("{}", query.question.qname), "www.google.com.");
        assert_eq!(query.question.qtype, QType::A);
        assert_eq!(query.question.qclass, QClass::IN);

        Ok(())
    }

    #[test]
    fn cap2() -> Result<()> {
        let pcap = get_packets("./tests/pcap/cap2.pcap", 0, 1);
        let mut buffer = std::io::Cursor::new(&pcap.0[0x2A..]);

        // check query
        let mut query = Query::default();
        query
            .header
            .deserialize_from(&mut buffer)
            .map_err(|_| Error::Dns(Dns::CantDeserialize))?;

        assert_eq!(query.header.flags.qr, PacketType::Query);
        assert_eq!(query.header.flags.op_code, OpCode::Query);
        assert!(!query.header.flags.bitflags.authorative_answer);
        assert!(!query.header.flags.bitflags.truncation);
        assert!(query.header.flags.bitflags.recursion_desired);
        assert!(!query.header.flags.bitflags.recursion_available);
        assert!(!query.header.flags.bitflags.z);
        assert!(query.header.flags.bitflags.authentic_data);
        assert_eq!(query.header.flags.response_code, ResponseCode::NoError);

        assert_eq!(query.header.qd_count, 1);
        assert_eq!(query.header.an_count, 0);
        assert_eq!(query.header.ns_count, 0);
        assert_eq!(query.header.ar_count, 1);

        // query.question.deserialize_from(&mut buffer)?;
        // assert_eq!(format!("{}", query.question.qname), "hk.");
        // assert_eq!(query.question.qtype, QType::NS);
        // assert_eq!(query.question.qclass, QClass::IN);

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
