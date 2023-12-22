use std::{
    net::{IpAddr, ToSocketAddrs, UdpSocket},
    time::Duration,
};

use log::debug;

use crate::error::DNSResult;

use super::{mode::TransportMode, Transporter};

pub struct UdpTransport {
    sock: UdpSocket,
}

impl UdpTransport {
    pub fn new<A: ToSocketAddrs>(addr: A, timeout: Duration) -> DNSResult<Self> {
        // let sock = if addr.is_ipv4() {
        //     UdpSocket::bind("0.0.0.0:0")?
        // } else {
        //     UdpSocket::bind("::")?
        // };

        let sock = UdpSocket::bind("0.0.0.0:0")?;

        sock.set_read_timeout(Some(timeout))?;
        sock.set_write_timeout(Some(timeout))?;

        sock.connect(addr)?;
        debug!("created UDP socket to {}", sock.peer_addr()?);
        Ok(Self { sock: sock })
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
}
