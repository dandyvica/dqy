use log::{info, trace};

// my DNS library
use dns::rfc::{
    domain::DomainName,
    message::{Message, MessageList},
    opt::{
        dau_dhu_n3u::{EdnsKeyTag, DAU, DHU, N3U},
        nsid::NSID,
        opt::OPT,
        padding::Padding,
    },
    qtype::QType,
    query::{MetaRR, Query},
    response::Response,
};

use args::{args::CliOptions, options::EdnsOptions};
use show::Show;
use transport::{protocol::Protocol, tcp::TcpProtocol, Transporter};

use crate::Info;

//a unit strutc with gathers all high level functions
pub(crate) struct DnsProtocol;

impl DnsProtocol {
    //───────────────────────────────────────────────────────────────────────────────────
    // build query from the cli options
    //───────────────────────────────────────────────────────────────────────────────────
    fn build_query(options: &CliOptions, qt: &QType) -> error::Result<Query> {
        //───────────────────────────────────────────────────────────────────────────────────
        // build the OPT record to be added in the additional section
        //───────────────────────────────────────────────────────────────────────────────────
        let opt = Self::build_opt(options.transport.bufsize, &options.edns);
        trace!("OPT record: {:#?}", &opt);

        //───────────────────────────────────────────────────────────────────────────────────
        // build Query
        //───────────────────────────────────────────────────────────────────────────────────
        let domain = DomainName::try_from(options.protocol.domain.as_str())?;

        let mut query = Query::build()
            .with_type(qt)
            .with_class(&options.protocol.qclass)
            .with_domain(domain)
            .with_flags(&options.flags);

        //───────────────────────────────────────────────────────────────────────────────────
        // Reserve length if TCP or TLS
        //───────────────────────────────────────────────────────────────────────────────────
        if options.transport.transport_mode.uses_leading_length() {
            query = query.with_length();
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // Add OPT if any
        //───────────────────────────────────────────────────────────────────────────────────
        if let Some(opt) = opt {
            query = query.with_additional(MetaRR::OPT(opt));
        }
        trace!("Query record: {:#?}", &query);

        Ok(query)
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // build OPT RR from the cli options
    //───────────────────────────────────────────────────────────────────────────────────
    fn build_opt(bufsize: u16, edns: &EdnsOptions) -> Option<OPT> {
        // --no-opt
        if edns.no_opt {
            return None;
        }

        let mut opt = OPT::build(bufsize);

        //───────────────────────────────────────────────────────────────────────────────
        // add OPT options according to cli options
        //───────────────────────────────────────────────────────────────────────────────

        // NSID
        if edns.nsid {
            opt.add_option(NSID::default());
        }

        // padding
        if let Some(len) = edns.padding {
            opt.add_option(Padding::new(len));
        }

        // DAU, DHU & N3U
        if let Some(list) = &edns.dau {
            opt.add_option(DAU::from(list.as_slice()));
        }
        if let Some(list) = &edns.dhu {
            opt.add_option(DHU::from(list.as_slice()));
        }
        if let Some(list) = &edns.n3u {
            opt.add_option(N3U::from(list.as_slice()));
        }

        // edns-key-tag
        if let Some(list) = &edns.keytag {
            opt.add_option(EdnsKeyTag::from(list.as_slice()));
        }

        // dnssec flag ?
        if edns.dnssec {
            opt.set_dnssec();
        }

        Some(opt)
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // send the query to the resolver
    //───────────────────────────────────────────────────────────────────────────────────
    fn send_query<T: Transporter>(
        options: &CliOptions,
        qt: &QType,
        trp: &mut T,
    ) -> error::Result<Query> {
        let mut query = Self::build_query(options, qt)?;

        // send query using the chosen transport
        let bytes = query.send(trp)?;
        info!(
            "sent query of {} bytes to remote address {}",
            bytes,
            trp.peer()?
        );

        Ok(query)
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // receive response from resolver
    //───────────────────────────────────────────────────────────────────────────────────
    fn receive_response<T: Transporter>(trp: &mut T, buffer: &mut [u8]) -> error::Result<Response> {
        let mut response = Response::default();
        let _ = response.recv(trp, buffer)?;

        Ok(response)
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // This sends and receive queries using a transport
    //───────────────────────────────────────────────────────────────────────────────────
    pub(crate) fn send_receive<T: Transporter>(
        options: &CliOptions,
        trp: &mut T,
        chuck_size: usize,
    ) -> error::Result<MessageList> {
        // we'll have the same number of messages than the number of types to query
        let mut v = Vec::with_capacity(options.protocol.qtype.len());

        for (i, qtype) in options.protocol.qtype.iter().enumerate() {
            let mut buffer = vec![0u8; 4096];

            // send query, response is depending on TC flag if UDP
            let query = Self::send_query(options, qtype, trp)?;
            let response = Self::receive_response(trp, &mut buffer)?;

            // check for the truncation (TC) header flag. If set and UDP, resend using TCP
            if response.tc() && trp.mode() == Protocol::Udp {
                info!("query for {} caused truncation, resending using TCP", qtype);
                buffer.clear();

                let mut tcp_transport = TcpProtocol::new(&options.transport)?;
                let query = Self::send_query(options, qtype, &mut tcp_transport)?;

                let buffer_slice = buffer
                    .get_mut(i * chuck_size..(i + 1) * chuck_size)
                    .unwrap();
                let response = Self::receive_response(&mut tcp_transport, buffer_slice)?;

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

    //───────────────────────────────────────────────────────────────────────────────────
    // check if response corresponds to what the client sent
    //───────────────────────────────────────────────────────────────────────────────────
    pub(crate) fn display(
        display_options: &show::DisplayOptions,
        info: &Info,
        messages: &MessageList,
    ) {
        // JSON
        if display_options.json_pretty {
            let j = serde_json::json!({
                "messages": messages,
                "info": info
            });
            println!("{}", serde_json::to_string_pretty(&j).unwrap());
        } else if display_options.json {
            let j = serde_json::json!({
                "messages": messages,
                "info": info
            });
            println!("{}", serde_json::to_string(&j).unwrap());
        } else {
            // if display_options.question {
            //     println!("{:?}", msg_list.query);
            // }
            for msg in messages.iter() {
                msg.response().show(display_options);
            }
        }
    }
}
