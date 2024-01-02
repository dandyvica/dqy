// Specific TLS handling
use std::{
    io::Write,
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
    str::FromStr
};

use log::debug;
// use log::debug;
use rustls::{ClientConnection, Stream};

use crate::error::{DNSResult, Error};

use super::{mode::TransportMode, Transporter};

pub struct TlsTransport<'a> {
    tls_stream: Stream<'a, ClientConnection, TcpStream>,
}

impl<'a> TlsTransport<'a> {
    pub fn new(tls: &'a mut (TcpStream, ClientConnection), timeout: Duration) -> DNSResult<Self> {
        tls.0.set_read_timeout(Some(timeout))?;
        tls.0.set_write_timeout(Some(timeout))?;
        let tls_stream = rustls::Stream::new(&mut tls.1, &mut tls.0);
        Ok(Self { tls_stream })
    }

    pub fn init_tls(server: &str, port: u16, timeout: Duration) -> DNSResult<(TcpStream, ClientConnection)> {
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

        // create the stream to the endpoint
        let destination = format!("{}:{}", server, port);
        let socket_addr = SocketAddr::from_str(&destination)?;
        let stream = if let Ok(s) = TcpStream::connect_timeout(&socket_addr, timeout) {
            s
        } else {
            return Err(Error::NoValidTCPConnection(vec![socket_addr]));
        };
        debug!("created TLS-TCP socket to {destination}");

        // build ServerName type which is used by ClientConnection::new()
        let server_name = server
            .try_into()
            .map_err(|_e| Error::Tls(rustls::Error::EncryptError))?;

        let conn = ClientConnection::new(Arc::new(config), server_name)?;

        Ok((stream, conn))
    }
}

impl<'a> Transporter for TlsTransport<'a> {
    fn send(&mut self, buffer: &[u8]) -> DNSResult<usize> {
        let sent = self.tls_stream.write(buffer)?;
        Ok(sent)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> DNSResult<usize> {
        <TlsTransport as Transporter>::tcp_read(&mut self.tls_stream, buffer)

        //Ok(self.tls_stream.read(buffer)?)
    }

    fn uses_leading_length(&self) -> bool {
        true
    }

    fn mode(&self) -> TransportMode {
        TransportMode::DoT
    }

    fn peer(&self) -> std::io::Result<SocketAddr> {
        self.tls_stream.sock.peer_addr()
    }
}
