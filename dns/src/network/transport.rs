// Transport for sending DNS messages

use std::{
    io::{BufReader, Read, Write},
    net::{IpAddr, TcpStream, UdpSocket},
    time::Duration,
};

use log::debug;
use rustls::{ClientConnection, Stream};
use ureq::{Agent, AgentBuilder, Response};

use crate::error::DNSResult;

use super::tls::TlsConnexion;

#[derive(Debug, Default, PartialEq)]
pub enum IPVersion {
    #[default]
    V4,
    V6,
}

#[derive(Debug, Default)]
pub enum TransportMode {
    #[default]
    Udp,
    Tcp,
    DoH,
    DoT,
}

impl TransportMode {
    pub fn is_dot(&self) -> bool {
        matches!(self, TransportMode::DoT)
    }

    pub fn uses_tcp(&self) -> bool {
        matches!(self, TransportMode::Tcp)
            || matches!(self, TransportMode::DoT)
            || matches!(self, TransportMode::DoH)
    }

    pub fn uses_tls(&self) -> bool {
        matches!(self, TransportMode::DoT) || matches!(self, TransportMode::DoH)
    }
}

#[derive(Debug)]
pub enum Transport<'a> {
    Udp {
        sock: UdpSocket,
    },
    Tcp {
        stream: TcpStream,
    },
    DoH {
        url: String,
        agent: Agent,
        resp: Option<Response>,
    },
    DoT {
        tls_stream: Stream<'a, ClientConnection, TcpStream>,
    },
}

impl<'a> Transport<'a> {
    pub fn new(
        tt: &TransportMode,
        ip: Option<&IpAddr>,
        port: u16,
        tls_conn: Option<&'a mut TlsConnexion>,
    ) -> std::io::Result<Self> {
        match tt {
            TransportMode::Udp => {
                let sock = UdpSocket::bind("0.0.0.0:0")?;
                let ip = ip.unwrap();
                sock.connect((*ip, port))?;
                debug!("created UDP socket to {}:{}", ip, port);
                Ok(Transport::Udp { sock })
            }
            TransportMode::Tcp => {
                let ip = ip.unwrap();
                let stream = TcpStream::connect((*ip, port))?;
                debug!("created TCP socket to {}:{}", ip, port);
                Ok(Transport::Tcp { stream })
            }
            TransportMode::DoH => {
                let agent = AgentBuilder::new().build();

                Ok(Transport::DoH {
                    url: String::from("https://dns.google/dns-query"),
                    agent: agent,
                    resp: None,
                })
            }
            TransportMode::DoT => {
                let tc = tls_conn.unwrap();

                Ok(Transport::DoT {
                    tls_stream: rustls::Stream::new(&mut tc.conn, &mut tc.sock),
                })
            }
        }
    }

    pub fn set_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            Transport::Udp { sock } => {
                sock.set_read_timeout(timeout)?;
                sock.set_write_timeout(timeout)
            }
            Transport::Tcp { stream } => {
                stream.set_read_timeout(timeout)?;
                stream.set_write_timeout(timeout)
            }
            Transport::DoT { tls_stream } => {
                tls_stream.sock.set_read_timeout(timeout)?;
                tls_stream.sock.set_write_timeout(timeout)
            }
            _ => unimplemented!("DoH not implemented"),
        }
    }

    // send data through UDP socket
    pub fn send(&mut self, buffer: &[u8]) -> DNSResult<usize> {
        match self {
            Transport::Udp { sock } => Ok(sock.send(&buffer)?),
            Transport::Tcp { ref mut stream } => {
                let sent = stream.write(buffer)?;
                stream.flush()?;
                Ok(sent)
            }
            Transport::DoH { url, agent, resp } => {
                let response = agent
                    .post(&url)
                    .set("Accept", "application/dns-message")
                    .set("Content-Type", "application/dns-message");
                *resp = Some(response);

                Ok(0)
            }
            Transport::DoT { tls_stream } => Ok(tls_stream.write(buffer)?),
            _ => unimplemented!("DoH not implemented"),
        }
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> DNSResult<usize> {
        match self {
            Transport::Udp { sock } => Ok(sock.recv(buffer)?),
            Transport::Tcp { ref mut stream } => {
                let mut reader = BufReader::new(stream);
                Ok(reader.read(buffer)?)
            }
            Transport::DoH { url, agent, resp } => {
                let r = resp.as_ref();
                let rr = r.unwrap();
                Ok(rr.into_reader().read(buffer)?)
            }
            Transport::DoT { tls_stream } => Ok(tls_stream.read(buffer)?),
            _ => unimplemented!("DoH not implemented"),
        }
    }

    pub fn uses_tcp(&self) -> bool {
        matches!(self, Transport::Tcp { .. }) || matches!(self, Transport::DoT { .. })
    }

    pub fn is_dot(&self) -> bool {
        matches!(self, Transport::DoT { .. })
    }
}
