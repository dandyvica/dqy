use std::fmt::Debug;
use std::io::Read;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use endpoint::EndPoint;
use http::version::Version;
use log::trace;

use error::{Error, Result};

// use self::https::HttpsProtocol;
use self::protocol::{IPVersion, Protocol};
// use self::tcp::TcpProtocol;
// use self::tls::TlsProtocol;
// use self::udp::UdpProtocol;

pub mod endpoint;
pub mod https;
pub mod protocol;
// pub mod quic;
pub mod tcp;
pub mod tls;
pub mod udp;

type NetworkStats = (usize, usize);

#[derive(Debug, Default)]
//───────────────────────────────────────────────────────────────────────────────────
// Transport options
//───────────────────────────────────────────────────────────────────────────────────
pub struct TransportOptions {
    // UPD, TCP, DoH or DoT
    pub transport_mode: Protocol,

    // V4 or V6
    pub ip_version: IPVersion,

    // timeout for network operations
    pub timeout: Duration,

    // resolver
    pub end_point: EndPoint,

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
    pub https_version: Version,

    // ip port destination (53 for udp/tcp, 853 for DoT, 443 for DoH)
    pub port: u16,

    // keep bytes sent and received
    pub bytes_sent: usize,
    pub bytes_received: usize,
}

pub trait Transporter {
    // send query using the underlying transport
    fn send(&mut self, buffer: &[u8]) -> Result<usize>;

    // receive response using the underlying transport
    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize>;

    // true if transporter uses Tcp. This is required for TCP transport to have 2 bytes
    // for the message length prepended in the query
    fn uses_leading_length(&self) -> bool;

    // return the transport mode
    fn mode(&self) -> Protocol;

    // read data from a TCP stream
    fn tcp_read<R>(stream: &mut R, buffer: &mut [u8]) -> Result<usize>
    where
        R: Read + Debug,
    {
        // in case of TCP, the first 2 bytes is lthe length of data coming
        // so read 2 first bytes
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        let length = u16::from_be_bytes(buf) as usize;

        trace!(
            "about to read {} bytes in the TCP stream {:?}",
            length,
            stream
        );

        // now read exact length
        stream.read_exact(&mut buffer[..length])?;

        Ok(length)
    }

    // return the remote address used by the transport
    fn peer(&self) -> std::io::Result<SocketAddr>;
}

// calls F depending on transport to be used
// pub fn transport<S: ToSocketAddrs>(
//     mode: &Protocol,
//     ip_version: &IPVersion,
//     timeout: Duration,
//     socketaddr: S,
// ) -> Result<Box<dyn Transporter>> {
//     match mode {
//         Protocol::Udp => {
//             let udp_transport = UdpProtocol::new(socketaddr, ip_version, timeout)?;
//             Ok(Box::new(udp_transport))
//         }
//         Protocol::Tcp => {
//             let tcp_transport = TcpProtocol::new(socketaddr, timeout)?;
//             Ok(Box::new(tcp_transport))
//         }
//         Protocol::DoT => {
//             let tls_transport = TlsProtocol::new("foo", timeout)?;
//             Ok(Box::new(tls_transport))
//         }
//         Protocol::DoH => {
//             let https_transport = HttpsProtocol::new("foo", timeout)?;
//             Ok(Box::new(https_transport))
//         }
//     }
// }

// Helper function to read TCP data
pub(crate) fn tcp_read<R>(stream: &mut R, buffer: &mut [u8]) -> Result<usize>
where
    R: Read + Debug,
{
    // in case of TCP, the first 2 bytes is lthe length of data coming
    // so read 2 first bytes
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf)?;
    let length = u16::from_be_bytes(buf) as usize;

    trace!(
        "about to read {} bytes in the TCP stream {:?}",
        length,
        stream
    );

    // now read exact length
    stream.read_exact(&mut buffer[..length])?;

    Ok(length)
}

// A helper function to get the TcpStream which connects succesfully
pub(crate) fn get_tcpstream_ok<A: ToSocketAddrs>(addrs: A, timeout: Duration) -> Result<TcpStream> {
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
        let addresses: Vec<SocketAddr> = addrs.to_socket_addrs()?.collect();
        return Err(Error::NoValidTCPConnection(addresses.to_vec()));
    }

    Ok(stream.unwrap())
}
