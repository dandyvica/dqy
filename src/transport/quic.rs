// Specific TLS handling
use std::{
    io::Write,
    net::{SocketAddr, TcpStream, UdpSocket},
    sync::Arc,
};

use error::{Error, Result};
use log::debug;
use rustls::{
    quic::{ClientConnection, Version},
    ClientConfig, RootCertStore, StreamOwned
};

use crate::{get_tcpstream_ok, TransportOptions, TransportProtocol};
use super::{protocol::Protocol, Transporter};

pub type QuicProtocol = TransportProtocol<StreamOwned<ClientConnection, UdpSocket>>;

impl QuicProtocol {
    pub fn new(trp_options: &TransportOptions) -> Result<Self> {
        // First we load some root certificates. These are used to authenticate the server.
        // The recommended way is to depend on the webpki_roots crate which contains the Mozilla set of root certificates.
        let root_store = Self::root_store();

        // Next, we make a ClientConfig. You’re likely to make one of these per process, and use it for all connections made by that process.
        let config = Self::config(root_store);

        let unspec = Self::unspec(&trp_options.ip_version);
        let sock = UdpSocket::bind(&unspec[..])?;
        debug!("created QUIC/UDP socket to {}", sock.peer_addr()?);

        // in case we use the host resolver, server name is empty. We need to fill it in
        let server = if trp_options.end_point.server.is_empty() {
            stream.peer_addr()?.ip().to_string()
        } else {
            trp_options.end_point.server.clone()
        };
        debug!("QUIC: server is {}", server);

        // build ServerName type which is used by ClientConnection::new()
        let server_name = server
            .to_string()
            .try_into()
            .map_err(|_e| Error::Tls(rustls::Error::EncryptError))?;

        let conn = ClientConnection::new(Arc::new(config), server_name)?;

        let tls_stream = StreamOwned::new(conn, stream);

        Ok(Self {
            stats: (0, 0),
            handle: tls_stream,
        })

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

impl Transporter for QuicProtocol {
    fn send(&mut self, buffer: &[u8]) -> Result<usize> {
        let sent = self.handle.write(buffer)?;
        Ok(sent)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let received = super::tcp_read(&mut self.handle, buffer)?;
        self.stats.1 = received;
        Ok(received)
    }

    fn uses_leading_length(&self) -> bool {
        true
    }

    fn mode(&self) -> Protocol {
        Protocol::DoQ
    }

    fn local(&self) -> std::io::Result<SocketAddr> {
        self.handle.sock.local_addr()
    }

    fn peer(&self) -> std::io::Result<SocketAddr> {
        self.handle.sock.peer_addr()
    }
}
