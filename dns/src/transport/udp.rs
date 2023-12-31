use std::{
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    time::Duration,
};

use log::{debug, trace};

use crate::error::DNSResult;

use super::{
    mode::{IPVersion, TransportMode},
    Transporter,
};

pub struct UdpTransport {
    sock: UdpSocket,
}

impl UdpTransport {
    pub fn new<A: ToSocketAddrs>(
        addr: A,
        ip_version: &IPVersion,
        timeout: Duration,
    ) -> DNSResult<Self> {
        let sock = if ip_version == &IPVersion::V4 {
            trace!("binding UDP socket to 0.0.0.0:0");
            UdpSocket::bind("0.0.0.0:0")?
        } else {
            trace!("binding UDP socket to ::");
            UdpSocket::bind("::")?
        };

        sock.set_read_timeout(Some(timeout))?;
        sock.set_write_timeout(Some(timeout))?;

        sock.connect(addr)?;
        debug!("created UDP socket to {}", sock.peer_addr()?);
        Ok(Self { sock })
    }
}

impl Transporter for UdpTransport {
    fn send(&mut self, buffer: &[u8]) -> DNSResult<usize> {
        Ok(self.sock.send(buffer)?)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> DNSResult<usize> {
        Ok(self.sock.recv(buffer)?)
    }

    fn uses_leading_length(&self) -> bool {
        false
    }

    fn mode(&self) -> TransportMode {
        TransportMode::Udp
    }

    fn peer(&self) -> std::io::Result<SocketAddr> {
        self.sock.peer_addr()
    }
}
