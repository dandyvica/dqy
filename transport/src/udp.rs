use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use log::debug;

use error::Result;

use crate::{TransportOptions, TransportProtocol};

use super::{
    protocol::{IPVersion, Protocol},
    Transporter,
};

pub type UdpProtocol = TransportProtocol<UdpSocket>;

impl UdpProtocol {
    pub fn new(trp_options: &TransportOptions) -> Result<Self> {
        // let sock = if trp_options.ip_version == IPVersion::V4 {
        //     trace!("binding UDP socket to 0.0.0.0:0");
        //     UdpSocket::bind("0.0.0.0:0")?
        // } else {
        //     trace!("binding UDP socket to ::");
        //     UdpSocket::bind("::")?
        // };

        let unspec = Self::unspec(&trp_options.ip_version);
        let sock = UdpSocket::bind(&unspec[..])?;
        debug!("bound UDP socket to {}", sock.local_addr()?);

        sock.set_read_timeout(Some(trp_options.timeout))?;
        sock.set_write_timeout(Some(trp_options.timeout))?;

        // connect() will chose any socket address which is succesful
        // as TransportOptions impl ToSocketAddrs
        sock.connect(&trp_options.end_point.addrs[..])?;
        debug!("created UDP socket to {}", sock.peer_addr()?);
        Ok(Self {
            stats: (0, 0),
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

impl Transporter for UdpProtocol {
    fn send(&mut self, buffer: &[u8]) -> Result<usize> {
        let sent = self.handle.send(buffer)?;
        self.stats.0 = sent;
        Ok(sent)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let received = self.handle.recv(buffer)?;
        self.stats.1 = received;
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
}
