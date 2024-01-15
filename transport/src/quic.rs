// Specific TLS handling
use std::{
    io::Write,
    net::{SocketAddr, TcpStream},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use error::{Error, Result};

use log::debug;
// use log::debug;
use crate::{get_tcpstream_ok, TransportOptions};
use rustls::{
    quic::{ClientConnection, Version},
    ClientConfig, RootCertStore, Stream,StreamOwned
};

use super::{protocol::Protocol, Transporter};

pub struct QuicTransport<'a> {
    tls_stream: Stream<'a, ClientConnection, TcpStream>,
}

impl<'a> QuicTransport<'a> {
    pub fn new(trp_options: &TransportOptions) -> Result<Self> {
        // First we load some root certificates. These are used to authenticate the server.
        // The recommended way is to depend on the webpki_roots crate which contains the Mozilla set of root certificates.
        let root_store = Self::root_store();

        // Next, we make a ClientConfig. You’re likely to make one of these per process, and use it for all connections made by that process.
        let config = Self::config(root_store);

        let stream = get_tcpstream_ok(&trp_options.end_point, trp_options.timeout)?;
        debug!("created QUIC socket to {}", stream.peer_addr()?);

        // build ServerName type which is used by ClientConnection::new()
        let server_name = trp_options
            .end_point
            .server()
            .unwrap()
            .to_string()
            .try_into()
            .map_err(|_e| Error::Tls(rustls::Error::EncryptError))?;

        let conn = ClientConnection::new(Arc::new(config), Version::V1, server_name, Vec::new())?;

        let tls_stream = StreamOwned::new(conn, stream);

        Ok(Self { tls_stream })
    }

    fn root_store() -> RootCertStore {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        root_store
    }

    fn config(root_store: RootCertStore) -> ClientConfig {
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    }
}

impl<'a> Transporter for QuicTransport<'a> {
    fn send(&mut self, buffer: &[u8]) -> DNSResult<usize> {
        let sent = self.tls_stream.write(buffer)?;
        Ok(sent)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> DNSResult<usize> {
        <QuicTransport as Transporter>::tcp_read(&mut self.tls_stream, buffer)

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
