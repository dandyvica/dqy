// Specific TLS handling
use std::{
    io::Write,
    net::{SocketAddr, TcpStream},
    sync::Arc,
};

use error::{Error, Result};
use log::debug;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use super::{protocol::Protocol, Transporter};
use crate::{get_tcpstream_ok, TransportOptions, TransportProtocol};

pub type TlsProtocol = TransportProtocol<StreamOwned<ClientConnection, TcpStream>>;

impl TlsProtocol {
    pub fn new(trp_options: &TransportOptions) -> Result<Self> {
        // First we load some root certificates. These are used to authenticate the server.
        // The recommended way is to depend on the webpki_roots crate which contains the Mozilla set of root certificates.
        let root_store = Self::root_store();

        // Next, we make a ClientConfig. You’re likely to make one of these per process, and use it for all connections made by that process.
        let config = Self::config(root_store);

        let stream = get_tcpstream_ok(&trp_options.end_point.addrs[..], trp_options.timeout)?;
        debug!("DoT: created TLS-TCP socket to {}", stream.peer_addr()?);

        // in case we use the host resolver, server name is empty. We need to fill it in
        let server = if trp_options.end_point.server.is_empty() {
            stream.peer_addr()?.ip().to_string()
        } else {
            trp_options.end_point.server.clone()
        };
        debug!("DoT: server is {}", server);

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

impl Transporter for TlsProtocol {
    fn send(&mut self, buffer: &[u8]) -> Result<usize> {
        let sent = self.handle.write(buffer)?;
        self.stats.0 = sent;
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
        Protocol::DoT
    }

    fn local(&self) -> std::io::Result<SocketAddr> {
        self.handle.sock.local_addr()
    }

    fn peer(&self) -> std::io::Result<SocketAddr> {
        self.handle.sock.peer_addr()
    }
}
