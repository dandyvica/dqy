use log::{debug, info};

use crate::dns::{
    message::{Message, MessageList},
    rfc::{qtype::QType, query::Query, response::Response},
};
use crate::network::{Messenger, Protocol};
use crate::transport::tcp::TcpProtocol;
use crate::{args::CliOptions, options::FromOptions};

// a unit struct with gathers all high level functions
pub(crate) struct DnsProtocol;

impl DnsProtocol {
    //───────────────────────────────────────────────────────────────────────────────────
    // send the query to the resolver
    //───────────────────────────────────────────────────────────────────────────────────
    fn send_query<T: Messenger>(
        options: &CliOptions,
        qt: &QType,
        trp: &mut T,
    ) -> crate::error::Result<Query> {
        // it's safe to unwrap here, see from_options() for Query
        let mut query = Query::from_options(options, qt).unwrap();

        //
        if trp.uses_leading_length() {
            query = query.with_length();
        }

        // send query using the chosen transport
        let bytes = query.send(trp)?;
        debug!(
            "sent query of {} bytes to remote address {}",
            bytes,
            trp.peer()?
        );

        Ok(query)
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // receive response from resolver
    //───────────────────────────────────────────────────────────────────────────────────
    #[inline(always)]
    fn receive_response<T: Messenger>(
        trp: &mut T,
        buffer: &mut [u8],
    ) -> crate::error::Result<Response> {
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
        let mut v = Vec::with_capacity(options.protocol.qtype.len());

        for qtype in options.protocol.qtype.iter() {
            let mut buffer = vec![0u8; buffer_size];

            // send query, response is depending on TC flag if UDP
            let query = Self::send_query(options, qtype, trp)?;
            let response = Self::receive_response(trp, &mut buffer)?;

            // check for the truncation (TC) header flag. If set and UDP, resend using TCP
            if response.is_truncated() && trp.mode() == Protocol::Udp {
                info!("query for {} caused truncation, resending using TCP", qtype);

                // otherwise, buffer will be empty is buffer.clear()
                buffer.fill(0);

                let mut tcp_transport = TcpProtocol::new(&options.transport)?;
                let query = Self::send_query(options, qtype, &mut tcp_transport)?;
                let response = Self::receive_response(&mut tcp_transport, &mut buffer)?;

                // struct Message is a convenient way
                let msg = Message { query, response };
                msg.check();
                v.push(msg);
                continue;
            }

            // struct Message is a convenient way
            let msg = Message { query, response };
            msg.check();
            v.push(msg);
        }

        Ok(MessageList::new(v))
    }
}
