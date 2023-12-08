use std::{
    io::{BufReader, Read, Write},
    net::{IpAddr, TcpStream},
    time::Duration,
};

use log::debug;

use crate::error::DNSResult;

use super::Transporter;

pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    pub fn new(ip: &IpAddr, port: u16, timeout: Option<Duration>) -> DNSResult<Self> {
        let stream = TcpStream::connect((*ip, port))?;
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;
        debug!("created TCP socket to {}:{}", ip, port);
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

    fn uses_tcp(&self) -> bool {
        true
    }
}
