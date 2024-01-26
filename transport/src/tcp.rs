use std::{
    io::Write,
    net::{SocketAddr, TcpStream},
};

use log::debug;

use error::Result;

use crate::{get_tcpstream_ok, NetworkStats, TransportOptions};

use super::{protocol::Protocol, Transporter};

pub struct TcpProtocol {
    pub stats: NetworkStats,
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
        Ok(Self {
            stats: (0, 0),
            stream,
        })
    }
}

impl Transporter for TcpProtocol {
    fn send(&mut self, buffer: &[u8]) -> Result<usize> {
        let sent = self.stream.write(buffer)?;
        self.stats.0 = sent;
        self.stream.flush()?;
        Ok(sent)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let received = super::tcp_read(&mut self.stream, buffer)?;
        self.stats.1 = received;
        Ok(received)
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
