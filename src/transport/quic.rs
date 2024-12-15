// Specific TLS handling
use std::{
    io::{ErrorKind, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
};

use log::{debug, info, trace};
use quinn::{crypto::rustls::QuicClientConfig, RecvStream, SendStream};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::{CertificateDer, ServerName};

use super::{
    crypto::{root_store, tls_config},
    endpoint::EndPoint,
    network::{unspec, AsyncMessenger, Messenger, Protocol},
};
use super::{NetworkStat, TransportOptions, TransportProtocol};
use crate::error::{self, Dns, Error, Network, QuicError, Result};

pub type QuicProtocol = TransportProtocol<(SendStream, RecvStream)>;

// ALPN bytes as stated here: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
const ALPN_DOQ: &[u8] = b"doq";

impl QuicProtocol {
    pub async fn new(trp_options: &TransportOptions) -> Result<Self> {
        // First we load some root certificates. These are used to authenticate the server.
        // The recommended way is to depend on the webpki_roots crate which contains the Mozilla set of root certificates.
        let root_store = root_store(&trp_options.cert)?;
        debug!("built root store with {} CAs", root_store.len());

        // Next, we make a TLS config. You’re likely to make one of these per process, and use it for all connections made by that process.
        let mut client_crypto = tls_config(root_store);

        // setting ALPN for DoQ is mandatory
        client_crypto.alpn_protocols = vec![ALPN_DOQ.to_vec()];

        // create a Quinn config
        let qcc =
            QuicClientConfig::try_from(client_crypto).map_err(|e| Error::Quic(QuicError::NoInitialCipherSuite))?;
        let client_config = quinn::ClientConfig::new(Arc::new(qcc));
        let mut quic_endpoint = quinn::Endpoint::client(unspec(&trp_options.ip_version)[0])
            .map_err(|e| Error::Network(e, Network::Bind))?;
        quic_endpoint.set_default_client_config(client_config);

        // let addr = "94.140.14.14:853".parse().unwrap();
        // let host = "dns.adguard.com";
        let addr = trp_options.endpoint.addrs[0];
        let host = &trp_options.endpoint.server_name;

        let conn = quic_endpoint
            .connect(addr, host)
            .unwrap()
            .await
            .map_err(|e| Error::Quic(QuicError::Connection(e)))?;

        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::Quic(QuicError::Connection(e)))?;

        Ok(Self {
            netstat: (0, 0),
            handle: (send, recv),
        })
    }
}

impl Messenger for QuicProtocol {
    fn send(&mut self, buffer: &[u8]) -> error::Result<usize> {
        Ok(0)
    }
    fn recv(&mut self, buffer: &mut [u8]) -> error::Result<usize> {
        Ok(0)
    }

    async fn asend(&mut self, buffer: &[u8]) -> Result<usize> {
        let sent = self
            .handle
            .0
            .write(buffer)
            .await
            .map_err(|e| Error::Quic(QuicError::Write(e)))?;
        self.netstat.0 = sent;
        //println!("quic sent");

        // if let Some(cs) = self.handle.conn.negotiated_cipher_suite() {
        //     info!("negociated ciphersuite: {:?}", cs);
        // }

        Ok(sent)
    }

    async fn arecv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        //println!("entering arecv()");

        let mut buf = [0u8; 2];
        self.handle
            .1
            .read_exact(&mut buf)
            .await
            .map_err(|e| Error::Quic(QuicError::ReadExact(e)))?;
        let length = u16::from_be_bytes(buf) as usize;

        //println!("about to read {} bytes in the TCP stream", length);

        // now read exact length
        self.handle
            .1
            .read_exact(&mut buffer[..length])
            .await
            .map_err(|e| Error::Quic(QuicError::ReadExact(e)))?;

        //println!("read {} bytes in the TCP stream", length);

        //println!("inside async recv, buffer={:X?}", buffer);

        self.netstat.1 = length;
        Ok(length)
    }

    fn uses_leading_length(&self) -> bool {
        true
    }

    fn mode(&self) -> Protocol {
        Protocol::DoQ
    }

    fn local(&self) -> std::io::Result<SocketAddr> {
        Err(std::io::Error::new(ErrorKind::Other, ""))
    }

    fn peer(&self) -> std::io::Result<SocketAddr> {
        Err(std::io::Error::new(ErrorKind::Other, ""))
    }

    fn netstat(&self) -> NetworkStat {
        self.stats()
    }
}

impl AsyncMessenger for QuicProtocol {
    async fn asend(&mut self, buffer: &[u8]) -> Result<usize> {
        let sent = self
            .handle
            .0
            .write(buffer)
            .await
            .map_err(|e| Error::Quic(QuicError::Write(e)))?;
        self.netstat.0 = sent;
        //println!("quic sent");

        // if let Some(cs) = self.handle.conn.negotiated_cipher_suite() {
        //     info!("negociated ciphersuite: {:?}", cs);
        // }

        Ok(sent)
    }

    async fn arecv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        //println!("entering arecv()");

        let mut buf = [0u8; 2];
        self.handle
            .1
            .read_exact(&mut buf)
            .await
            .map_err(|e| Error::Quic(QuicError::ReadExact(e)))?;
        let length = u16::from_be_bytes(buf) as usize;

        //println!("about to read {} bytes in the TCP stream", length);

        // now read exact length
        self.handle
            .1
            .read_exact(&mut buffer[..length])
            .await
            .map_err(|e| Error::Quic(QuicError::ReadExact(e)))?;

        //println!("read {} bytes in the TCP stream", length);

        //println!("inside async recv, buffer={:X?}", buffer);

        self.netstat.1 = length;
        Ok(length)
    }

    fn uses_leading_length(&self) -> bool {
        true
    }

    fn mode(&self) -> Protocol {
        Protocol::DoQ
    }

    // fn local(&self) -> std::io::Result<SocketAddr> {
    //     self.handle.sock.local_addr()
    // }

    // fn peer(&self) -> std::io::Result<SocketAddr> {
    //     self.handle.sock.peer_addr()
    // }

    // fn netstat(&self) -> NetworkStat {
    //     self.stats()
    // }
}
