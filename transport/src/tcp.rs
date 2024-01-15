use std::{
    io::Write,
    net::{SocketAddr, TcpStream},
};

use log::debug;

use error::Result;

use crate::{get_tcpstream_ok, TransportOptions};

use super::{protocol::Protocol, Transporter};

pub struct TcpProtocol {
    stream: TcpStream,
}

impl TcpProtocol {
    pub fn new(trp_options: &TransportOptions) -> Result<Self> {
        let stream = get_tcpstream_ok(&trp_options.end_point, trp_options.timeout)?;

        // now it's safe to unwrap
        //let tcp_stream = stream.unwrap();
        stream.set_read_timeout(Some(trp_options.timeout))?;
        stream.set_write_timeout(Some(trp_options.timeout))?;

        debug!("created TCP socket to {}", stream.peer_addr()?);
        Ok(Self { stream })
    }
}

impl Transporter for TcpProtocol {
    fn send(&mut self, buffer: &[u8]) -> Result<usize> {
        let sent = self.stream.write(buffer)?;
        self.stream.flush()?;
        Ok(sent)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        super::tcp_read(&mut self.stream, buffer)
    }

    fn uses_leading_length(&self) -> bool {
        true
    }

    fn mode(&self) -> Protocol {
        Protocol::Tcp
    }

    fn peer(&self) -> std::io::Result<SocketAddr> {
        self.stream.peer_addr()
    }
}
