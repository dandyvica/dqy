// Transport for sending DNS messages

use std::net::{IpAddr, TcpStream, UdpSocket};

use log::debug;

use crate::error::{DNSError, DNSResult, InternalError};

pub struct Transport {
    pub udp_socket: UdpSocket,
    tcp_socket: Option<TcpStream>,
}

impl Transport {
    pub fn new() -> Self {
        match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => Transport {
                udp_socket: socket,
                tcp_socket: None,
            },
            Err(e) => {
                eprintln!("error {} binding UDP socket", e);
                std::process::exit(1);
            }
        }
    }

    // send data through UDP socket
    pub fn send_to(
        &self,
        buffer: &[u8],
        dns_resolvers: &[IpAddr],
        port: u16,
    ) -> DNSResult<(IpAddr, usize)> {
        for ip_addr in dns_resolvers {
            if let Ok(bytes) = self
                .udp_socket
                .send_to(&buffer, format!("{}:{}", ip_addr, port))
            {
                return Ok((*ip_addr, bytes));
            } else {
                debug!("can't send message to ip {}", ip_addr);
            }
        }

        Err(DNSError::new_internal(InternalError::UnreachableResolvers))
    }

    pub fn recv(&self, buffer: &mut [u8]) -> DNSResult<usize> {
        Ok(self.udp_socket.recv(buffer)?)
    }
}
