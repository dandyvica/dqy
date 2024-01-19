//! A comination of a query and a response
//!

use std::ops::Deref;

use super::{query::Query, response::Response, response_code::ResponseCode};

use log::error;
use serde::Serialize;

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
    pub fn check(&self) {
        if self.response.id() != self.query.header.id
            || self.query.question != self.response.question
        {
            error!(
                "query and response ID are not equal, discarding answer for type {:?}",
                self.query.question.qtype
            );
        }

        // check return code
        if self.response.rcode() != ResponseCode::NoError
            || (self.response.rcode() == ResponseCode::NXDomain && self.response.ns_count() == 0)
        {
            eprintln!("response error:{}", self.response.rcode());
        }
    }
}

//───────────────────────────────────────────────────────────────────────────────────
// convenient struct for holding al messages
//───────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Serialize)]
pub struct MessageList(Vec<Message>);

impl MessageList {
    pub fn new(list: Vec<Message>) -> Self {
        Self(list)
    }
}

impl Deref for MessageList {
    type Target = Vec<Message>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
