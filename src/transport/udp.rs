use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use log::debug;

use super::network::{IPVersion, Messenger, Protocol};
use super::{NetworkStat, TransportOptions, TransportProtocol};
use crate::error::{Error, Network, Result};

pub type UdpProtocol = TransportProtocol<UdpSocket>;

impl UdpProtocol {
    pub fn new(trp_options: &TransportOptions) -> Result<Self> {
        let unspec = Self::unspec(&trp_options.ip_version);
        let sock = UdpSocket::bind(&unspec[..]).map_err(|e| Error::Network(e, Network::Bind))?;

        debug!(
            "bound UDP socket to {}",
            sock.local_addr().map_err(|e| Error::Network(e, Network::LocalAddr))?
        );

        sock.set_read_timeout(Some(trp_options.timeout))
            .map_err(|e| Error::Timeout(e, trp_options.timeout))?;
        sock.set_write_timeout(Some(trp_options.timeout))
            .map_err(|e| Error::Timeout(e, trp_options.timeout))?;

        // connect() will chose any socket address which is succesful
        // as TransportOptions impl ToSocketAddrs
        sock.connect(&trp_options.endpoint.addrs[..])
            .map_err(|e| Error::Network(e, Network::Connect))?;

        debug!(
            "created UDP socket to {}",
            sock.peer_addr().map_err(|e| Error::Network(e, Network::PeerAddr))?
        );

        Ok(Self {
            netstat: (0, 0),
            handle: sock,
        })
    }

    // Bind to a socket either to IPV4, IPV6 or any of these 2
    // the bind() method will chose the first one which succeeds if IPVersion::Any is passed
    fn unspec(ver: &IPVersion) -> Vec<SocketAddr> {
        match ver {
            IPVersion::Any => vec![
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            ],
            IPVersion::V4 => vec![SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))],
            IPVersion::V6 => vec![SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))],
        }
    }
}

impl Messenger for UdpProtocol {
    fn send(&mut self, buffer: &[u8]) -> Result<usize> {
        let sent = self.handle.send(buffer).map_err(|e| Error::Network(e, Network::Send))?;
        self.netstat.0 = sent;

        debug!("sent {} bytes", sent);

        Ok(sent)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let received = self
            .handle
            .recv(buffer)
            .map_err(|e| Error::Network(e, Network::Receive))?;
        self.netstat.1 = received;

        debug!("received {} bytes", received);

        Ok(received)
    }

    fn uses_leading_length(&self) -> bool {
        false
    }

    fn mode(&self) -> Protocol {
        Protocol::Udp
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
