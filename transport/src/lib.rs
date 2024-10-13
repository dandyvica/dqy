use std::fmt::Debug;
use std::io::Read;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use endpoint::EndPoint;
use http::version::Version;
// use https::HttpsProtocol;
use log::trace;

use error::{Error, Result};
// use tcp::TcpProtocol;
// use tls::TlsProtocol;
// use udp::UdpProtocol;

// use self::https::HttpsProtocol;
use self::protocol::{IPVersion, Protocol};
// use self::tcp::TcpProtocol;
// use self::tls::TlsProtocol;
// use self::udp::UdpProtocol;

pub mod endpoint;
pub mod https;
pub mod protocol;
// pub mod quic;
pub mod root_servers;
pub mod tcp;
pub mod tls;
pub mod udp;

// number of bytes sent and received for DNS operations
type NetworkStat = (usize, usize);

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

    // V4 or V6
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
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            transport_mode: Protocol::default(),
            ip_version: IPVersion::default(),
            timeout: Duration::from_millis(3000),
            endpoint: EndPoint::default(),
            stats: false,
            bufsize: 1232,
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
        }
    }
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
    // fn tcp_read<R>(stream: &mut R, buffer: &mut [u8]) -> Result<usize>
    // where
    //     R: Read + Debug, Self: Sized
    // {
    //     // in case of TCP, the first 2 bytes is lthe length of data coming
    //     // so read 2 first bytes
    //     let mut buf = [0u8; 2];
    //     stream.read_exact(&mut buf)?;
    //     let length = u16::from_be_bytes(buf) as usize;

    //     trace!(
    //         "about to read {} bytes in the TCP stream {:?}",
    //         length,
    //         stream
    //     );

    //     // now read exact length
    //     stream.read_exact(&mut buffer[..length])?;

    //     Ok(length)
    // }

    // return the local address used by the transport
    fn local(&self) -> std::io::Result<SocketAddr>;

    // return the remote address used by the transport
    fn peer(&self) -> std::io::Result<SocketAddr>;

    // return the network stats in the underlying structure
    fn netstat(&self) -> NetworkStat;
}

// calls F depending on transport to be used
// type Binop = fn(&dyn Transporter) -> error::Result<()>;

// pub fn call_transport<F, P>(trp_options: &TransportOptions, f: F) -> error::Result<()>
// where
//     F: Fn(Transporter) -> error::Result<()>,
//     P: Transporter
// {
//     match trp_options.transport_mode {
//         Protocol::Udp => {
//             let trp = UdpProtocol::new(&trp_options)?;
//             f(trp)
//         }
//         Protocol::Tcp => {
//             let trp = TcpProtocol::new(&trp_options)?;
//             f(trp)
//         }
//         Protocol::DoT => {
//             let trp = TlsProtocol::new(&trp_options)?;
//             f(trp)
//         }
//         Protocol::DoH => {
//             let trp = HttpsProtocol::new(&trp_options)?;
//             f(trp)
//         }
//     }
// }

// pub fn init_transport(trp_options: &TransportOptions) -> error::Result<Box<dyn Transporter + '_>> {
//     match trp_options.transport_mode {
//         Protocol::Udp => {
//             let trp = UdpProtocol::new(&trp_options)?;
//             Ok(Box::new(trp))
//         }
//         Protocol::Tcp => {
//             let trp = TcpProtocol::new(&trp_options)?;
//             Ok(Box::new(trp))
//         }
//         Protocol::DoT => {
//             let trp = TlsProtocol::new(&trp_options)?;
//             Ok(Box::new(trp))
//         }
//         Protocol::DoH => {
//             let trp = HttpsProtocol::new(&trp_options)?;
//             Ok(Box::new(trp))
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

    trace!("inside tcp_read, buffer={:X?}", buffer);

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
