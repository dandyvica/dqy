use std::{
    io::{BufReader, Read, Write},
    net::{IpAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

use log::debug;

use crate::error::DNSResult;

use super::{mode::TransportMode, Transporter};

pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    pub fn new<A: ToSocketAddrs>(addr: A, timeout: Duration) -> DNSResult<Self> {
        let stream = TcpStream::connect(addr)?;

        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        debug!("created TCP socket to {}", stream.peer_addr()?);
        Ok(Self { stream: stream })
    }
}

impl Transporter for TcpTransport {
    fn send(&mut self, buffer: &[u8]) -> DNSResult<usize> {
        let sent = self.stream.write(buffer)?;
        self.stream.flush()?;
        Ok(sent)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> DNSResult<usize> {
        let mut reader = BufReader::new(&self.stream);
        Ok(reader.read(buffer)?)
    }

    fn uses_leading_length(&self) -> bool {
        true
    }

    fn mode(&self) -> TransportMode {
        TransportMode::Tcp
    }
}
