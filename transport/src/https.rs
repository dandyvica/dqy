// Transport for sending DNS messages

use std::net::SocketAddr;

use bytes::Bytes;
use http::version::*;

use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT},
};

use error::Result;

use crate::{NetworkStats, TransportOptions};

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

    // bytes sent & received
    pub stats: NetworkStats,
}

impl<'a> HttpsProtocol<'a> {
    pub fn new(trp_options: &'a TransportOptions) -> Result<Self> {
        let x = Client::builder()
            // same headers for all requests
            .default_headers(Self::construct_headers())
            // HTTP/2 by default as recommended by RFC8484
            // .http2_prior_knowledge()
            .timeout(trp_options.timeout);

        let client = match trp_options.https_version {
            Version::HTTP_11 => x.http1_only().build()?,
            Version::HTTP_2 => x.http2_prior_knowledge().build()?,
            _ => unimplemented!(
                "version {:?} of HTTP is not yet implemented",
                trp_options.https_version
            ),
        };

        debug_assert!(trp_options.end_point.server().is_some());
        let server = trp_options.end_point.server().unwrap();

        Ok(Self {
            server,
            client,
            bytes_recv: Bytes::default(),
            peer: None,
            stats: (0, 0),
        })
    }

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
        self.stats.0 = bytes_sent.len();

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
        let received = self.bytes_recv.len();
        self.stats.1 = received;

        // copy Bytes to buffer
        buffer[..received].copy_from_slice(&self.bytes_recv);

        Ok(received)
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
