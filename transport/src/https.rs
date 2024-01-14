// Transport for sending DNS messages

use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use http::version::*;

use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT},
};

use error::Result;

use super::{protocol::Protocol, Transporter};

pub struct HttpsProtocol<'a> {
    // URL endpoint
    server: &'a str,

    // reqwest client used to send DNS messages
    client: Client,

    // data received from Response
    bytes_recv: Bytes,

    // peer address to which the client is connected
    peer: Option<SocketAddr>,
}

impl<'a> HttpsProtocol<'a> {
    pub fn new(server: &'a str, timeout: Duration, http_version: Version) -> Result<Self> {
        let x = Client::builder()
            // same headers for all requests
            .default_headers(Self::construct_headers())
            // HTTP/2 by default as recommended by RFC8484
            // .http2_prior_knowledge()
            .timeout(timeout);

        let client = match http_version {
            HTTP_11 => x.http1_only().build()?,
            HTTP_2 => x.http2_prior_knowledge().build()?,
            _ => unimplemented!("version {:?} of HTTP is not yet implemented", http_version),
        };

        Ok(Self {
            server,
            client,
            bytes_recv: Bytes::default(),
            peer: None,
        })
    }
    // pub fn new(server: &'a str, timeout: Duration) -> Result<Self> {
    //     let client = Client::builder()
    //         // same headers for all requests
    //         .default_headers(Self::construct_headers())
    //         // HTTP/2 by default as recommended by RFC8484
    //         .http2_prior_knowledge()
    //         .timeout(timeout)
    //         .build()?;

    //     Ok(Self {
    //         server,
    //         client,
    //         bytes_recv: Bytes::default(),
    //         peer: None,
    //     })
    // }

    fn construct_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("reqwest"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/dns-message"));
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/dns-message"),
        );
        headers
    }
}

impl<'a> Transporter for HttpsProtocol<'a> {
    fn send(&mut self, buffer: &[u8]) -> Result<usize> {
        // need to copy bytes because body() prototype is: pub fn body<T: Into<Body>>(self, body: T) -> RequestBuilder
        // and From<Body> is not implemented for &[u8]. See here: https://docs.rs/reqwest/latest/reqwest/blocking/struct.Body.html
        // it can then be consumed by the body() method
        let bytes_sent = Bytes::copy_from_slice(buffer);

        // add buffer length as content-length header. header() method consume the RequestBuilder and returns a new one
        let resp = self
            .client
            .post(self.server)
            .header(CONTENT_LENGTH, buffer.len())
            .body(bytes_sent)
            .send()?;

        // save remote address
        self.peer = resp.remote_addr();

        // and extract the bytes received
        self.bytes_recv = resp.bytes()?;

        Ok(buffer.len())
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let len = self.bytes_recv.len();
        // copy Bytes to buffer
        buffer[..len].copy_from_slice(&self.bytes_recv);

        Ok(self.bytes_recv.len())
    }

    // don't add the message length even if it's TCP
    fn uses_leading_length(&self) -> bool {
        false
    }

    fn mode(&self) -> Protocol {
        Protocol::DoH
    }

    fn peer(&self) -> std::io::Result<SocketAddr> {
        self.peer.ok_or(std::io::Error::other(
            "unable to get remote peer from HTTPS response",
        ))
    }
}
