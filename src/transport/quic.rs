// Specific TLS handling
use std::{
    io::Write,
    net::{SocketAddr, TcpStream},
    sync::Arc,
};

use log::{debug, info};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::{CertificateDer, ServerName};

use super::{
    endpoint::EndPoint,
    network::{Messenger, Protocol},
};
use super::{get_tcpstream_ok, NetworkStat, TransportOptions, TransportProtocol};
use crate::error::{Dns, Error, Network, Result};

pub type QuicProtocol = TransportProtocol<StreamOwned<ClientConnection, TcpStream>>;

// ALPN bytes as stated here: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
const ALPN_DOQ: &[u8] = b"doq";

impl QuicProtocol {
    pub fn new(trp_options: &TransportOptions) -> Result<Self> {
        // First we load some root certificates. These are used to authenticate the server.
        // The recommended way is to depend on the webpki_roots crate which contains the Mozilla set of root certificates.
        let root_store = Self::root_store(&trp_options.cert)?;
        debug!("built root store with {} CAs", root_store.len());

        // Next, we make a ClientConfig. You’re likely to make one of these per process, and use it for all connections made by that process.
        let mut config = Self::config(root_store);

        if trp_options.alpn {
            config.alpn_protocols = vec![ALPN_DOQ.to_vec()];
        }

        // as EndPoint addrs can contain several addresses, we get the first address for which
        // we can create a TcpStream. This is the case when we pass e.g.: one.one.one.one:853
        let (stream, addr) = get_tcpstream_ok(&trp_options.endpoint.addrs[..], trp_options.timeout)?;
        debug!("created TLS-TCP socket to {}", addr);

        let server_name = Self::build_server_name(&trp_options.endpoint, &addr)?;
        debug!("server name: {:?}", server_name);

        let conn = ClientConnection::new(Arc::new(config), server_name).map_err(Error::Tls)?;
        let tls_stream = StreamOwned::new(conn, stream);

        Ok(Self {
            netstat: (0, 0),
            handle: tls_stream,
        })
    }

    // build server name used by ClientConnection::new()
    fn build_server_name(ep: &EndPoint, addr: &SocketAddr) -> Result<ServerName<'static>> {
        // use SNI if set
        if let Some(sni) = &ep.sni {
            ServerName::try_from(sni.clone()).map_err(|_| Error::Dns(Dns::InvalidSNI))
        }
        // or target ip addr
        else {
            Ok(ServerName::from(addr.ip()))
        }
    }

    // manage CAs
    fn root_store(cert: &Option<Vec<u8>>) -> Result<RootCertStore> {
        let mut root_store = rustls::RootCertStore::empty();

        // we've got a certificate here
        if let Some(buf) = cert {
            let cert = CertificateDer::from_slice(buf);
            root_store.add(cert).map_err(Error::Tls)?;
        }
        // use root CAs
        else {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        Ok(root_store)
    }

    // build a new client config
    fn config(root_store: RootCertStore) -> ClientConfig {
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    }
}

impl Messenger for QuicProtocol {
    fn send(&mut self, buffer: &[u8]) -> Result<usize> {
        let sent = self
            .handle
            .write(buffer)
            .map_err(|e| Error::Network(e, Network::Send))?;
        self.netstat.0 = sent;

        if let Some(cs) = self.handle.conn.negotiated_cipher_suite() {
            info!("negociated ciphersuite: {:?}", cs);
        }

        Ok(sent)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let received = super::tcp_read(&mut self.handle, buffer)?;
        self.netstat.1 = received;
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

    fn netstat(&self) -> NetworkStat {
        self.stats()
    }
}
