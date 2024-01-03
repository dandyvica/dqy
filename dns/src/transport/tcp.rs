use std::{
    io::Write,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

use log::debug;

use crate::error::{DNSResult, Error};

use super::{mode::TransportMode, Transporter};

pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    pub fn new<A: ToSocketAddrs>(addrs: A, timeout: Duration) -> DNSResult<Self> {
        let mut stream: Option<TcpStream> = None;

        // find the first address for which the connexion succeeds
        for addr in addrs.to_socket_addrs()? {
            if let Ok(s) = TcpStream::connect_timeout(&addr, timeout) {
                stream = Some(s);
                break;
            }
        }

        // if None, none of the connexions is OK
        if stream.is_none() {
            let addresses: Vec<SocketAddr> = addrs.to_socket_addrs()?.into_iter().collect();
            return Err(Error::NoValidTCPConnection(addresses));
        }

        // now it's safe to unwrap
        let tcp_stream = stream.unwrap();
        tcp_stream.set_read_timeout(Some(timeout))?;
        tcp_stream.set_write_timeout(Some(timeout))?;

        debug!("created TCP socket to {}", tcp_stream.peer_addr()?);
        Ok(Self { stream: tcp_stream })
    }
}

impl Transporter for TcpTransport {
    fn send(&mut self, buffer: &[u8]) -> DNSResult<usize> {
        let sent = self.stream.write(buffer)?;
        self.stream.flush()?;
        Ok(sent)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> DNSResult<usize> {
        <TcpTransport as Transporter>::tcp_read(&mut self.stream, buffer)
    }

    fn uses_leading_length(&self) -> bool {
        true
    }

    fn mode(&self) -> TransportMode {
        TransportMode::Tcp
    }

    fn peer(&self) -> std::io::Result<SocketAddr> {
        self.stream.peer_addr()
    }
}
