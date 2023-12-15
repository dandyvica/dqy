use crate::error::DNSResult;

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
    fn uses_tcp(&self) -> bool;

    // only true for UDP
    fn is_udp(&self) -> bool;
}
