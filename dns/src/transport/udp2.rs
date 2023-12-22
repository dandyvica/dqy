use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket},
    time::Duration,
};

use log::debug;

use crate::err_internal;
use crate::error::{DNSResult, Error, ProtocolError};

use super::Transporter;

// primary & optional secondary DNS resolvers
pub type Endpoint = (SocketAddr, Option<SocketAddr>);

pub struct UdpTransport2 {
    // index of the working socket
    index: Option<usize>,

    // sockets created for primary and optionnally to secondary resolvers
    sock_list: Vec<UdpSocket>,
}

impl UdpTransport2 {
    pub fn new<A: ToSocketAddrs>(addrs: A, timeout: Duration) -> DNSResult<Self> {
        // create all sockets to each address.
        // connect() doesn't detect whether the endpoint is accessible, only at send()
        // do this to get consistent with other transports
        let mut sock_list = Vec::new();

        // create sockets for addresses
        for addr in addrs.to_socket_addrs()? {
            let socket = Self::create_socket(addr, timeout)?;
            debug!("created UDP socket for endpoint {addr}");
            sock_list.push(socket);
        }

        Ok(Self {
            // no socket is working so far
            index: None,
            sock_list,
        })
    }

    // create a socket and set timeouts
    fn create_socket(addr: SocketAddr, timeout: Duration) -> DNSResult<UdpSocket> {
        let sock = if addr.is_ipv4() {
            UdpSocket::bind("0.0.0.0:0")?
        } else {
            UdpSocket::bind("::")?
        };

        // set timeouts. There's no timeout for connect()
        sock.set_read_timeout(Some(timeout))?;
        sock.set_write_timeout(Some(timeout))?;

        // connect but OS can't detect if endpoint is accessible
        sock.connect(addr)?;

        Ok(sock)
    }

    // loca
}

impl Transporter for UdpTransport2 {
    fn send(&mut self, buffer: &[u8]) -> DNSResult<usize> {
        // did we already use a working socket ?
        if let Some(i) = self.index {
            let working_sock = self.sock_list.get(i);
            debug_assert!(working_sock.is_some());

            Ok(working_sock.unwrap().send(buffer)?)
        }
        // no socket we already tried to use, so test it one by one
        else {
            let mut send_bytes = 0usize;
            for sock in self.sock_list.iter().enumerate() {
                if let Ok(bytes) = sock.1.send(buffer) {
                    self.index = Some(sock.0);
                    send_bytes = bytes;
                }
            }
            // we should have a valid index now !
            if self.index.is_none() {
                return Err(err_internal!(UnreachableResolvers));
            } else {
                Ok(send_bytes)
            }
        }
    }

    fn recv(&mut self, buffer: &mut [u8]) -> DNSResult<usize> {
        debug_assert!(self.index.is_some());
        let sock = &self.sock_list[self.index.unwrap()];
        Ok(sock.recv(buffer)?)
    }

    fn uses_leading_length(&self) -> bool {
        false
    }

    fn is_udp(&self) -> bool {
        true
    }
}
