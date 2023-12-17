// Specific TLS handling
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

// use log::debug;
use rustls::{ClientConnection, Stream};

use crate::error::DNSResult;

use super::Transporter;

pub struct TlsTransport<'a> {
    tls_stream: Stream<'a, ClientConnection, TcpStream>,
}

impl<'a> TlsTransport<'a> {
    pub fn new(
        tls: &'a mut (TcpStream, ClientConnection),
        timeout: Option<Duration>,
    ) -> DNSResult<Self> {
        tls.0.set_read_timeout(timeout)?;
        tls.0.set_write_timeout(timeout)?;
        let tls_stream = rustls::Stream::new(&mut tls.1, &mut tls.0);
        Ok(Self { tls_stream })
    }

    pub fn init_tls(server: &str, port: usize) -> DNSResult<(TcpStream, ClientConnection)> {
        // First we load some root certificates. These are used to authenticate the server.
        // The recommended way is to depend on the webpki_roots crate which contains the Mozilla set of root certificates.
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        // Next, we make a ClientConfig. You’re likely to make one of these per process, and use it for all connections made by that process.
        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name = server.try_into().unwrap();
        let destination = format!("{}:{}", server, port);

        let sock = TcpStream::connect(destination)?;
        let conn = ClientConnection::new(Arc::new(config), server_name)?;

        Ok((sock, conn))
    }
}

impl<'a> Transporter for TlsTransport<'a> {
    fn send(&mut self, buffer: &[u8]) -> DNSResult<usize> {
        Ok(self.tls_stream.write(buffer)?)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> DNSResult<usize> {
        Ok(self.tls_stream.read(buffer)?)
    }

    fn uses_leading_length(&self) -> bool {
        true
    }

    fn is_udp(&self) -> bool {
        false
    }
}
