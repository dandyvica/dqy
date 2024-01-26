use std::net::{SocketAddr, UdpSocket};

use log::{debug, trace};

use error::Result;

use crate::{NetworkStats, TransportOptions};

use super::{
    protocol::{IPVersion, Protocol},
    Transporter,
};

pub struct UdpProtocol {
    pub stats: NetworkStats,
    sock: UdpSocket,
}

impl UdpProtocol {
    pub fn new(trp_options: &TransportOptions) -> Result<Self> {
        let sock = if trp_options.ip_version == IPVersion::V4 {
            trace!("binding UDP socket to 0.0.0.0:0");
            UdpSocket::bind("0.0.0.0:0")?
        } else {
            trace!("binding UDP socket to ::");
            UdpSocket::bind("::")?
        };

        sock.set_read_timeout(Some(trp_options.timeout))?;
        sock.set_write_timeout(Some(trp_options.timeout))?;

        // connect() will chose any socket address which is succesful
        // as TransportOptions impl ToSocketAddrs
        sock.connect(&trp_options.end_point)?;
        debug!("created UDP socket to {}", sock.peer_addr()?);
        Ok(Self {
            stats: (0, 0),
            sock,
        })
    }
}

impl Transporter for UdpProtocol {
    fn send(&mut self, buffer: &[u8]) -> Result<usize> {
        let sent = self.sock.send(buffer)?;
        self.stats.0 = sent;
        Ok(sent)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let received = self.sock.recv(buffer)?;
        self.stats.1 = received;
        Ok(received)
    }

    fn uses_leading_length(&self) -> bool {
        false
    }

    fn mode(&self) -> Protocol {
        Protocol::Udp
    }

    fn peer(&self) -> std::io::Result<SocketAddr> {
        self.sock.peer_addr()
    }
}
