// Transport for sending DNS messages
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::Bytes;
use http::version::*;
use log::debug;
use reqwest::{
    blocking::{Client, ClientBuilder},
    header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT},
};

use super::network::{IPVersion, Messenger, Protocol};
use super::{NetworkStat, TransportOptions};
use crate::error::{self, Error, Result};

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
    pub stats: NetworkStat,
}

impl<'a> HttpsProtocol<'a> {
    pub fn new(trp_options: &'a TransportOptions) -> crate::error::Result<Self> {
        let client = Self::client_builder(trp_options)?.build().map_err(Error::Reqwest)?;

        debug_assert!(!trp_options.endpoint.server_name.is_empty());
        let server = &trp_options.endpoint.server_name;
        debug!("server: {}", server);

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
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/dns-message"));
        headers
    }

    fn client_builder(trp_options: &'a TransportOptions) -> Result<ClientBuilder> {
        // same headers for all requests
        let mut cb = Client::builder()
            .default_headers(Self::construct_headers())
            .timeout(trp_options.timeout)
            .connect_timeout(trp_options.timeout)
            .https_only(true)
            .use_rustls_tls();

        // do we have a PEM certificate?
        if let Some(buf) = &trp_options.cert {
            // load CERT
            let cert = reqwest::Certificate::from_pem(buf).map_err(Error::Reqwest)?;
            cb = cb.add_root_certificate(cert);
        }

        // set ip version to use
        cb = match trp_options.ip_version {
            IPVersion::Any => cb,
            IPVersion::V4 => cb.local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            IPVersion::V6 => cb.local_address(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        };

        // http version to use
        cb = match trp_options.https_version {
            Some(Version::HTTP_11) => cb.http1_only(),
            Some(Version::HTTP_2) => cb.http2_prior_knowledge(),
            // Some(Version::HTTP_3) => cb.http3_prior_knowledge().build().map_err(|e| Error::Reqwest(e))?,
            _ => unimplemented!("version {:?} of HTTP is not yet implemented", trp_options.https_version),
        };

        Ok(cb)
    }
}

impl<'a> Messenger for HttpsProtocol<'a> {
    async fn asend(&mut self, _: &[u8]) -> error::Result<usize> {
        Ok(0)
    }
    async fn arecv(&mut self, _: &mut [u8]) -> error::Result<usize> {
        Ok(0)
    }

    fn send(&mut self, buffer: &[u8]) -> crate::error::Result<usize> {
        self.stats.0 = buffer.len();

        // add buffer length as content-length header. header() method consume the RequestBuilder and returns a new one
        let resp = self
            .client
            .post(self.server)
            .header(CONTENT_LENGTH, buffer.len())
            .body(buffer.to_vec())
            .send()
            .map_err(Error::Reqwest)?;

        // save remote address
        self.peer = resp.remote_addr();

        // and extract the bytes received
        self.bytes_recv = resp.bytes().map_err(Error::Reqwest)?;

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

    fn local(&self) -> std::io::Result<SocketAddr> {
        Ok("0.0.0.0:0".parse().unwrap())
    }

    fn peer(&self) -> std::io::Result<SocketAddr> {
        self.peer
            .ok_or(std::io::Error::other("unable to get remote peer from HTTPS response"))
    }

    fn netstat(&self) -> NetworkStat {
        self.stats
    }
}
