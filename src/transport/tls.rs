// Specific TLS handling
use std::{
    io::Write,
    net::{SocketAddr, TcpStream},
    sync::Arc,
};

use log::{debug, info};
use rustls::{ClientConnection, StreamOwned};
use rustls_pki_types::ServerName;

use super::{
    crypto::{root_store, tls_config},
    endpoint::EndPoint,
    network::{Messenger, Protocol},
};
use super::{get_tcpstream_ok, TransportOptions, TransportProtocol};
use crate::{
    error::{self, Dns, Error, Network, Result},
    transport::NetworkInfo,
};

pub type TlsProtocol = TransportProtocol<StreamOwned<ClientConnection, TcpStream>>;

// ALPN bytes as stated here: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
const ALPN_DOT: &[u8] = b"dot";

impl TlsProtocol {
    pub fn new(trp_options: &TransportOptions) -> Result<Self> {
        // First we load some root certificates. These are used to authenticate the server.
        // The recommended way is to depend on the webpki_roots crate which contains the Mozilla set of root certificates.
        let root_store = root_store(&trp_options.cert)?;
        debug!("built root store with {} CAs", root_store.len());

        // Next, we make a ClientConfig. You’re likely to make one of these per process, and use it for all connections made by that process.
        let mut config = tls_config(root_store);

        if trp_options.alpn {
            config.alpn_protocols = vec![ALPN_DOT.to_vec()];
        }

        // as EndPoint addrs can contain several addresses, we get the first address for which
        // we can create a TcpStream. This is the case when we pass e.g.: one.one.one.one:853
        let (stream, addr) = get_tcpstream_ok(&trp_options.endpoint.addrs[..], trp_options.timeout)?;
        debug!("created TLS-TCP socket to {}", addr);

        let server_name = Self::build_server_name(&trp_options.endpoint, &addr)?;
        debug!("server name: {:?}", server_name);

        let conn = ClientConnection::new(Arc::new(config), server_name).map_err(Error::Tls)?;
        let tls_stream = StreamOwned::new(conn, stream);

        let peer = tls_stream.sock.peer_addr().ok();

        Ok(Self {
            handle: tls_stream,
            netinfo: NetworkInfo {
                sent: 0,
                received: 0,
                peer,
            },
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
}

impl Messenger for TlsProtocol {
    async fn asend(&mut self, _: &[u8]) -> error::Result<usize> {
        Ok(0)
    }
    async fn arecv(&mut self, _: &mut [u8]) -> error::Result<usize> {
        Ok(0)
    }

    fn send(&mut self, buffer: &[u8]) -> Result<usize> {
        self.netinfo.sent = self
            .handle
            .write(buffer)
            .map_err(|e| Error::Network(e, Network::Send))?;

        if let Some(cs) = self.handle.conn.negotiated_cipher_suite() {
            info!("negociated ciphersuite: {:?}", cs);
        }

        Ok(self.netinfo.sent)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.netinfo.received = super::tcp_read(&mut self.handle, buffer)?;
        Ok(self.netinfo.received)
    }

    fn uses_leading_length(&self) -> bool {
        true
    }

    fn mode(&self) -> Protocol {
        Protocol::DoT
    }

    fn network_info(&self) -> &NetworkInfo {
        self.netinfo()
    }

    // fn local(&self) -> std::io::Result<SocketAddr> {
    //     self.handle.sock.local_addr()
    // }

    // fn peer(&self) -> std::io::Result<SocketAddr> {
    //     self.handle.sock.peer_addr()
    // }
}
