use std::{
    io::Write,
    net::{SocketAddr, TcpStream},
};

use log::debug;

use super::network::{Messenger, Protocol};
use super::{get_tcpstream_ok, NetworkStat, TransportOptions, TransportProtocol};
use crate::error::{Error, Network, Result};

pub type TcpProtocol = TransportProtocol<TcpStream>;

impl TcpProtocol {
    pub fn new(trp_options: &TransportOptions) -> Result<Self> {
        let (handle, _) = get_tcpstream_ok(&trp_options.endpoint.addrs[..], trp_options.timeout)?;

        handle
            .set_read_timeout(Some(trp_options.timeout))
            .map_err(|e| crate::error::Error::Timeout(e, trp_options.timeout))?;
        handle
            .set_write_timeout(Some(trp_options.timeout))
            .map_err(|e| crate::error::Error::Timeout(e, trp_options.timeout))?;

        debug!(
            "created TCP socket to {}",
            handle.peer_addr().map_err(|e| Error::Network(e, Network::PeerAddr))?
        );

        Ok(Self {
            netstat: (0, 0),
            handle,
        })
    }
}

impl Messenger for TcpProtocol {
    fn send(&mut self, buffer: &[u8]) -> Result<usize> {
        let sent = self.handle.write(buffer).map_err(|e| crate::error::Error::Buffer(e))?;
        self.netstat.0 = sent;
        self.handle.flush().map_err(|e| crate::error::Error::Buffer(e))?;
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
        Protocol::Tcp
    }

    fn local(&self) -> std::io::Result<SocketAddr> {
        self.handle.local_addr()
    }

    fn peer(&self) -> std::io::Result<SocketAddr> {
        self.handle.peer_addr()
    }

    fn netstat(&self) -> NetworkStat {
        self.stats()
    }
}
