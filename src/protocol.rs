use std::fs::File;
use std::io::Write;

use log::{debug, info};

use crate::error::Error;
use crate::transport::network::{Messenger, Protocol};
use crate::transport::tcp::TcpProtocol;
use crate::{args::CliOptions, cli_options::FromOptions};
use crate::{
    dns::{
        message::{Message, MessageList},
        rfc::{qtype::QType, query::Query, response::Response},
    },
    error::Network,
};

// a unit struct with gathers all high level functions
pub(crate) struct DnsProtocol;

impl DnsProtocol {
    //───────────────────────────────────────────────────────────────────────────────────
    // send the query to the resolver
    //───────────────────────────────────────────────────────────────────────────────────
    fn send_query<T: Messenger>(options: &CliOptions, qt: &QType, trp: &mut T) -> crate::error::Result<Query> {
        // it's safe to unwrap here, see from_options() for Query
        let mut query = Query::from_options(options, qt).unwrap();

        // TCP needs to prepend with 2 bytes for message length
        if trp.uses_leading_length() {
            query = query.with_length();
        }

        // send query using the chosen transport
        let bytes = query.send(trp, &options.dump.write_query)?;
        debug!(
            "sent query of {} bytes to remote address {}",
            bytes,
            trp.peer().map_err(|e| Error::Network(e, Network::PeerAddr))?
        );

        Ok(query)
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // receive response from resolver
    //───────────────────────────────────────────────────────────────────────────────────
    #[inline(always)]
    fn receive_response<T: Messenger>(trp: &mut T, buffer: &mut [u8]) -> crate::error::Result<Response> {
        let mut response = Response::default();
        let _ = response.recv(trp, buffer)?;

        Ok(response)
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // this sends and receives queries using a transport
    //───────────────────────────────────────────────────────────────────────────────────
    pub(crate) fn process_request<T: Messenger>(
        options: &CliOptions,
        trp: &mut T,
        buffer_size: usize,
    ) -> crate::error::Result<MessageList> {
        // we'll have the same number of messages than the number of types to query
        let mut messages = Vec::with_capacity(options.protocol.qtype.len());
        let mut buffer = vec![0u8; buffer_size];

        for qtype in options.protocol.qtype.iter() {
            // send query, response is depending on TC flag if UDP
            let mut query = Self::send_query(options, qtype, trp)?;
            let mut response = Self::receive_response(trp, &mut buffer)?;

            // check for the truncation (TC) header flag. If set and UDP, resend using TCP
            if response.is_truncated() && trp.mode() == Protocol::Udp {
                info!("query for {} caused truncation, resending using TCP", qtype);

                // clear buffer using fill(), otherwise buffer will be empty if buffer.clear()
                buffer.fill(0);

                // resend using TCP
                let mut tcp_transport = TcpProtocol::new(&options.transport)?;
                query = Self::send_query(options, qtype, &mut tcp_transport)?;
                response = Self::receive_response(&mut tcp_transport, &mut buffer)?;
            }

            // struct Message is a convenient way to gather both query and response
            let msg = Message { query, response };
            msg.check()?;
            messages.push(msg);
        }

        Ok(MessageList::new(messages))
    }
}
