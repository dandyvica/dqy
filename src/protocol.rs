use std::path::PathBuf;

use log::{debug, info};

use crate::dns::{
    message::{Message, MessageList},
    rfc::{qtype::QType, query::Query, response::Response},
};
use crate::error::{self};
use crate::transport::network::{Messenger, Protocol};
use crate::transport::tcp::TcpProtocol;
use crate::{args::CliOptions, cli_options::FromOptions};

// a unit struct with gathers all high level functions
pub(crate) struct DnsProtocol;

impl DnsProtocol {
    //───────────────────────────────────────────────────────────────────────────────────
    // send the query to the resolver
    //───────────────────────────────────────────────────────────────────────────────────
    fn send_query<T: Messenger>(options: &CliOptions, qt: &QType, trp: &mut T) -> error::Result<Query> {
        // it's safe to unwrap here, see from_options() for Query
        let mut query = Query::from_options(options, qt).unwrap();

        // TCP needs to prepend with 2 bytes for message length
        if trp.uses_leading_length() {
            query = query.with_length();
        }

        // send query using the chosen transport
        let bytes = query.send(trp, &options.dump.write_query)?;
        debug!(
            "sent query of {} bytes to remote address {:?}",
            bytes,
            trp.network_info().peer
        );

        Ok(query)
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // send the query to the resolver, async version
    //───────────────────────────────────────────────────────────────────────────────────
    async fn asend_query<T: Messenger>(options: &CliOptions, qt: &QType, trp: &mut T) -> error::Result<Query> {
        // it's safe to unwrap here, see from_options() for Query
        let mut query = Query::from_options(options, qt).unwrap();

        // TCP needs to prepend with 2 bytes for message length
        if trp.uses_leading_length() {
            query = query.with_length();
        }

        // send query using the chosen transport
        let bytes = query.asend(trp, &options.dump.write_query).await?;
        debug!(
            "sent query of {} bytes to remote address {:?}",
            bytes,
            trp.network_info().peer
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
        save_path: &Option<PathBuf>,
    ) -> crate::error::Result<Response> {
        let mut response = Response::default();
        let _ = response.recv(trp, buffer, save_path)?;

        Ok(response)
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // receive response from resolver, async version
    //───────────────────────────────────────────────────────────────────────────────────
    #[inline(always)]
    async fn areceive_response<T: Messenger>(
        trp: &mut T,
        buffer: &mut [u8],
        save_path: &Option<PathBuf>,
    ) -> crate::error::Result<Response> {
        let mut response = Response::default();
        let _ = response.arecv(trp, buffer, save_path).await?;

        Ok(response)
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // this sends and receives queries using a sync transport
    //───────────────────────────────────────────────────────────────────────────────────
    pub(crate) fn sync_process_request<T: Messenger>(
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
            let mut response = Self::receive_response(trp, &mut buffer, &options.dump.write_response)?;

            // check for the truncation (TC) header flag. If set and UDP, resend using TCP
            if response.is_truncated() && trp.mode() == Protocol::Udp {
                info!("query for {} caused truncation, resending using TCP", qtype);

                // clear buffer using fill(), otherwise buffer will be empty if buffer.clear()
                buffer.fill(0);

                // resend using TCP
                let mut tcp_transport = TcpProtocol::new(&options.transport)?;
                query = Self::send_query(options, qtype, &mut tcp_transport)?;
                response = Self::receive_response(&mut tcp_transport, &mut buffer, &options.dump.write_response)?;
            }

            // struct Message is a convenient way to gather both query and response
            let msg = Message { query, response };
            msg.check()?;
            messages.push(msg);
        }

        Ok(MessageList::new(messages))
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // this sends and receives queries using an async transport
    //───────────────────────────────────────────────────────────────────────────────────
    pub(crate) async fn async_process_request<T: Messenger>(
        options: &CliOptions,
        trp: &mut T,
        buffer_size: usize,
    ) -> crate::error::Result<MessageList> {
        // we'll have the same number of messages than the number of types to query
        let mut messages = Vec::with_capacity(options.protocol.qtype.len());
        let mut buffer = vec![0u8; buffer_size];

        for qtype in options.protocol.qtype.iter() {
            // for QUIC, we need a specific stream for each query as stated in https://www.rfc-editor.org/rfc/rfc9250.html
            trp.aconnect().await?;

            // send query, response is depending on TC flag if UDP
            let query = Self::asend_query(options, qtype, trp).await?;
            let response = Self::areceive_response(trp, &mut buffer, &options.dump.write_response).await?;

            // struct Message is a convenient way to gather both query and response
            let msg = Message { query, response };
            msg.check()?;
            messages.push(msg);
        }

        Ok(MessageList::new(messages))
    }
}
