//! A comination of a query and a response
//!
use std::{fmt, ops::Deref};

use super::rfc::{query::Query, response::Response, response_code::ResponseCode};

use log::{error, trace};
use serde::Serialize;

use crate::show::{header_section, DisplayOptions, QueryInfo, Show, ShowAll};

#[derive(Debug, Serialize)]
pub struct Message {
    pub query: Query,
    pub response: Response,
}

impl Message {
    //───────────────────────────────────────────────────────────────────────────────────
    // return a reference to the query part
    //───────────────────────────────────────────────────────────────────────────────────
    pub fn query(&self) -> &Query {
        &self.query
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // return a reference to the response part
    //───────────────────────────────────────────────────────────────────────────────────
    pub fn response(&self) -> &Response {
        &self.response
    }

    //───────────────────────────────────────────────────────────────────────────────────
    // check if response corresponds to what the client sent
    //───────────────────────────────────────────────────────────────────────────────────
    pub fn check(&self) -> crate::error::Result<()> {
        trace!("checking message validity");

        if self.response.id() != self.query.header.id || self.query.question != self.response.question {
            error!(
                "query and response ID are not equal, discarding answer for type {:?}",
                self.query.question.qtype
            );
        }

        // if self.response.rcode() != ResponseCode::NoError {
        //     return Err(crate::error::Error::Internal(ProtocolError::ResponseError(
        //         self.response.rcode(),
        //     )));
        // }

        // check return code
        if self.response.rcode() != ResponseCode::NoError
            || (self.response.rcode() == ResponseCode::NXDomain && self.response.ns_count() == 0)
        {
            eprintln!("response error:{}", self.response.rcode());
        }

        Ok(())
    }

    // Return the max length of the response part
    #[inline]
    pub fn max_length(&self) -> usize {
        self.response.max_length()
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.query)?;
        write!(f, "{}", self.response)?;
        Ok(())
    }
}

impl Show for Message {
    fn show(&self, display_options: &DisplayOptions, length: Option<usize>) {
        // print out Query if requested
        if display_options.show_question {
            self.query.show(display_options, length);
        }

        self.response.show(display_options, length);
    }
}

//───────────────────────────────────────────────────────────────────────────────────
// convenient struct for holding all messages
//───────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Serialize)]
pub struct MessageList(Vec<Message>);

impl MessageList {
    pub fn new(list: Vec<Message>) -> Self {
        Self(list)
    }

    // Return the max length of all messages (all RRs of all messages)
    pub fn max_length(&self) -> Option<usize> {
        self.0.iter().map(|x| x.max_length()).max()
    }
}

impl Deref for MessageList {
    type Target = Vec<Message>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for MessageList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for msg in self.iter() {
            write!(f, "{}", msg)?;
        }
        Ok(())
    }
}

impl ShowAll for MessageList {
    fn show_all(&self, display_options: &mut DisplayOptions, info: QueryInfo) {
        //───────────────────────────────────────────────────────────────────────────────────
        // JSON
        //───────────────────────────────────────────────────────────────────────────────────
        if display_options.json_pretty {
            let j = serde_json::json!({
                "messages": self,
                "info": info
            });
            println!("{}", serde_json::to_string_pretty(&j).unwrap());
            return;
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // JSON pretty
        //───────────────────────────────────────────────────────────────────────────────────
        if display_options.json {
            let j = serde_json::json!({
                "messages": self,
                "info": info
            });
            println!("{}", serde_json::to_string(&j).unwrap());
            return;
        }

        //───────────────────────────────────────────────────────────────────────────────────
        // fancy print out when only one message
        //───────────────────────────────────────────────────────────────────────────────────
        if self.len() == 1 {
            // we only have 1 message
            let msg = &self[0];
            let resp = msg.response();

            // when we only have one message, we print out a dig-like info
            display_options.sho_resp_header = true;
            display_options.show_headers = true;
            display_options.show_all = true;

            resp.show(display_options, None);

            // print out stats
            println!("{}", header_section("STATS", None));
            println!("{}", info);
        }
        //───────────────────────────────────────────────────────────────────────────────────
        // when several messages, just print out the ANSWER
        //───────────────────────────────────────────────────────────────────────────────────
        else {
            let max_length = self.max_length();

            for msg in self.iter() {
                msg.show(display_options, max_length);
            }

            if display_options.stats {
                println!("{}", info);
            }
        }
    }
}
