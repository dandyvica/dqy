use std::fmt::Debug;
use std::io::Read;

use log::trace;

use crate::error::DNSResult;

use self::mode::TransportMode;

pub mod https;
pub mod mode;
pub mod tcp;
pub mod tls;
pub mod udp;

pub trait Transporter {
    // send query using the underlying transport
    fn send(&mut self, buffer: &[u8]) -> DNSResult<usize>;

    // receive response using the underlying transport
    fn recv(&mut self, buffer: &mut [u8]) -> DNSResult<usize>;

    // true if transporter uses Tcp. This is required for TCP transport to have 2 bytes
    // for the message length prepended in the query
    fn uses_leading_length(&self) -> bool;

    // return the transport mode
    fn mode(&self) -> TransportMode;

    // read data from a TCP stream
    fn tcp_read<R>(stream: &mut R, buffer: &mut [u8]) -> DNSResult<usize>
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
}
