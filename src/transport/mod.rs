use std::fmt::Debug;
use std::io::{ErrorKind, Read};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use endpoint::EndPoint;
use http::version::Version;
use log::trace;

use crate::error::{Error, Network, Result};
use network::{IPVersion, Protocol};

pub mod endpoint;
pub mod https;
pub mod network;
// pub mod quic;
pub mod root_servers;
pub mod tcp;
pub mod tls;
pub mod udp;

// number of bytes sent and received for DNS operations
type NetworkStat = (usize, usize);

// default UDP buffer size
const BUFFER_SIZE: u16 = 1232;
const DEFAULT_TIMEOUT: u64 = 3000;

pub struct TransportProtocol<T> {
    pub netstat: NetworkStat,

    //handle is either a socket or a stream
    handle: T,
}

impl<T> TransportProtocol<T> {
    pub fn stats(&self) -> NetworkStat {
        self.netstat
    }
}

#[derive(Debug, Clone)]
//───────────────────────────────────────────────────────────────────────────────────
// Transport options
//───────────────────────────────────────────────────────────────────────────────────
pub struct TransportOptions {
    // UPD, TCP, DoH or DoT
    pub transport_mode: Protocol,

    // V4 or V6 or Any
    pub ip_version: IPVersion,

    // timeout for network operations
    pub timeout: Duration,

    // resolver
    pub endpoint: EndPoint,

    // if true, elasped time and some stats are printed out
    pub stats: bool,

    // buffer size of EDNS0
    pub bufsize: u16,

    // true if TLS/DoT
    pub tls: bool,
    pub dot: bool,

    // true if TCP
    pub tcp: bool,

    // true if HTTPS/DOH
    pub https: bool,
    pub doh: bool,

    // http version
    pub https_version: Option<Version>,

    // true if DNS over Quic
    pub doq: bool,

    // ip port destination (53 for udp/tcp, 853 for DoT, 443 for DoH)
    pub port: u16,

    // keep bytes sent and received
    pub bytes_sent: usize,
    pub bytes_received: usize,

    // set DoT ALPN
    pub alpn: bool,

    // optional certificate file as PEM
    pub cert: Option<Vec<u8>>,

    // encrypted client hello
    pub ech: bool,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            transport_mode: Protocol::default(),
            ip_version: IPVersion::default(),
            timeout: Duration::from_millis(DEFAULT_TIMEOUT),
            endpoint: EndPoint::default(),
            stats: false,
            bufsize: BUFFER_SIZE,
            tls: false,
            dot: false,
            tcp: false,
            https: false,
            doh: false,
            https_version: None,
            doq: false,
            port: 53,
            bytes_sent: 0,
            bytes_received: 0,
            alpn: false,
            cert: None,
            ech: false,
        }
    }
}

// Helper function to read TCP data
pub(crate) fn tcp_read<R>(stream: &mut R, buffer: &mut [u8]) -> Result<usize>
where
    R: Read + Debug,
{
    // in case of TCP, the first 2 bytes is lthe length of data coming
    // so read 2 first bytes

    let mut buf = [0u8; 2];
    stream
        .read_exact(&mut buf)
        .map_err(|e| Error::Network(e, Network::Read))?;
    let length = u16::from_be_bytes(buf) as usize;

    trace!("about to read {} bytes in the TCP stream {:?}", length, stream);

    // now read exact length
    stream
        .read_exact(&mut buffer[..length])
        .map_err(|e| Error::Network(e, Network::Read))?;

    trace!("inside tcp_read, buffer={:X?}", buffer);

    Ok(length)
}

// Connect to the first address for which connection succeeds
pub(crate) fn get_tcpstream_ok<A: ToSocketAddrs>(addrs: A, timeout: Duration) -> Result<(TcpStream, SocketAddr)> {
    // find the first address for which the connexion succeeds
    for addr in addrs
        .to_socket_addrs()
        .map_err(|e| Error::Network(e, Network::SocketAddr))?
    {
        if let Ok(s) = TcpStream::connect_timeout(&addr, timeout) {
            return Ok((s, addr));
        }
    }

    let err = std::io::Error::from(ErrorKind::AddrNotAvailable);
    return Err(Error::Network(err, Network::Connect));
}
