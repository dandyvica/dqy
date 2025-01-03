use std::net::UdpSocket;

use log::debug;

use super::network::{Messenger, Protocol};
use super::{TransportOptions, TransportProtocol};
use crate::error::{self, Error, Network, Result};
use crate::transport::NetworkInfo;

pub type UdpProtocol = TransportProtocol<UdpSocket>;

impl UdpProtocol {
    pub fn new(trp_options: &TransportOptions) -> Result<Self> {
        let unspec = trp_options.ip_version.unspecified_ip_vec();
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

        let peer = sock.peer_addr().ok();
        debug!("created UDP socket to {:?}", peer);

        Ok(Self {
            handle: sock,
            netinfo: NetworkInfo {
                sent: 0,
                received: 0,
                peer,
            },
        })
    }

    // // Bind to a socket either to IPV4, IPV6 or any of these 2
    // // the bind() method will chose the first one which succeeds if IPVersion::Any is passed
    // fn unspec(ver: &IPVersion) -> Vec<SocketAddr> {
    //     match ver {
    //         IPVersion::Any => vec![
    //             SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
    //             SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    //         ],
    //         IPVersion::V4 => vec![SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))],
    //         IPVersion::V6 => vec![SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))],
    //     }
    // }
}

impl Messenger for UdpProtocol {
    async fn asend(&mut self, _: &[u8]) -> error::Result<usize> {
        Ok(0)
    }
    async fn arecv(&mut self, _: &mut [u8]) -> error::Result<usize> {
        Ok(0)
    }

    fn send(&mut self, buffer: &[u8]) -> Result<usize> {
        self.netinfo.sent = self.handle.send(buffer).map_err(|e| Error::Network(e, Network::Send))?;
        debug!("sent {} bytes", self.netinfo.sent);

        Ok(self.netinfo.sent)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.netinfo.received = self
            .handle
            .recv(buffer)
            .map_err(|e| Error::Network(e, Network::Receive))?;
        debug!("received {} bytes", self.netinfo.received);

        Ok(self.netinfo.received)
    }

    fn uses_leading_length(&self) -> bool {
        false
    }

    fn mode(&self) -> Protocol {
        Protocol::Udp
    }

    fn network_info(&self) -> &NetworkInfo {
        self.netinfo()
    }

    // fn local(&self) -> std::io::Result<SocketAddr> {
    //     self.handle.local_addr()
    // }

    // fn peer(&self) -> std::io::Result<SocketAddr> {
    //     self.handle.peer_addr()
    // }
}
