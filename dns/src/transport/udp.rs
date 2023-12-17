use std::{
    net::{IpAddr, UdpSocket},
    time::Duration,
};

use log::debug;

use crate::error::DNSResult;

use super::Transporter;

pub struct UdpTransport {
    sock: UdpSocket,
}

impl UdpTransport {
    pub fn new(ip: &IpAddr, port: u16, timeout: Option<Duration>) -> DNSResult<Self> {
        let sock = if ip.is_ipv4() {
            UdpSocket::bind("0.0.0.0:0")?
        } else {
            UdpSocket::bind("::")?
        };

        sock.set_read_timeout(timeout)?;
        sock.set_write_timeout(timeout)?;

        sock.connect((*ip, port))?;
        debug!("created UDP socket to {}:{}", ip, port);
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

    fn is_udp(&self) -> bool {
        true
    }
}
