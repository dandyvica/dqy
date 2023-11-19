// Transport for sending DNS messages

use std::{
    io::{BufReader, Read, Write},
    net::{IpAddr, TcpStream, UdpSocket}, time::Duration,
};

use log::debug;

use crate::error::DNSResult;

#[derive(Debug, Default, PartialEq)]
pub enum IPVersion {
    #[default]
    V4,
    V6,
}

#[derive(Debug, Default, PartialEq)]
pub enum TransportType {
    #[default]
    Udp,
    Tcp,
    Doh,
    Dot,
}

#[derive(Debug)]
pub enum Transport {
    Udp { sock: UdpSocket },
    Tcp { stream: TcpStream },
    Doh,
    Dot,
}

impl Transport {
    pub fn new(tt: &TransportType, ip: IpAddr, port: u16) -> std::io::Result<Self> {
        match tt {
            TransportType::Udp => {
                let sock = UdpSocket::bind("0.0.0.0:0")?;
                sock.connect((ip, port))?;
                debug!("created UDP socket to {}:{}", ip, port);
                Ok(Transport::Udp { sock })
            }
            TransportType::Tcp => {
                let stream = TcpStream::connect((ip, port))?;
                debug!("created TCP socket to {}:{}", ip, port);
                Ok(Transport::Tcp { stream })
            }
            _ => unimplemented!("not implemented"),
        }
    }

    pub fn set_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()>  {
        match self {
            Transport::Udp{sock} => {
                sock.set_read_timeout(timeout)?;
                sock.set_write_timeout(timeout)

            }
            Transport::Tcp{stream} => {
                stream.set_read_timeout(timeout)?;
                stream.set_write_timeout(timeout)
            }
            _ => unimplemented!("not implemented"),
        }
    }

}

impl Transport {
    // send data through UDP socket
    pub fn send(&mut self, buffer: &[u8]) -> DNSResult<usize> {
        match self {
            Transport::Udp { sock } => Ok(sock.send(&buffer)?),
            Transport::Tcp { ref mut stream } => {
                let sent = stream.write(buffer)?;
                stream.flush()?;
                Ok(sent)
            }
            _ => unimplemented!(),
        }
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> DNSResult<usize> {
        match self {
            Transport::Udp { sock } => Ok(sock.recv(buffer)?),
            Transport::Tcp { ref mut stream } => {
                let mut reader = BufReader::new(stream);
                Ok(reader.read(buffer)?)
            }
            _ => unimplemented!(),
        }
    }

    pub fn is_tcp(&self) -> bool {
        matches!(self, Transport::Tcp { .. })
    }
}
