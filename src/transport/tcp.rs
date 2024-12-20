use std::{io::Write, net::TcpStream};

use log::debug;

use super::network::{Messenger, Protocol};
use super::{get_tcpstream_ok, TransportOptions, TransportProtocol};
use crate::{
    error::{self, Result},
    transport::NetworkInfo,
};

pub type TcpProtocol = TransportProtocol<TcpStream>;

impl TcpProtocol {
    pub fn new(trp_options: &TransportOptions) -> Result<Self> {
        let (handle, _) = get_tcpstream_ok(&trp_options.endpoint.addrs[..], trp_options.timeout)?;

        handle
            .set_read_timeout(Some(trp_options.timeout))
            .map_err(|e| crate::error::Error::Timeout(e, trp_options.timeout))?;
        handle
            .set_write_timeout(Some(trp_options.timeout))
            .map_err(|e| crate::error::Error::Timeout(e, trp_options.timeout))?;

        let peer = handle.peer_addr().ok();
        debug!("created TCP socket to {:?}", peer);

        Ok(Self {
            handle,
            netinfo: NetworkInfo {
                sent: 0,
                received: 0,
                peer,
            },
        })
    }
}

impl Messenger for TcpProtocol {
    async fn asend(&mut self, _: &[u8]) -> error::Result<usize> {
        Ok(0)
    }
    async fn arecv(&mut self, _: &mut [u8]) -> error::Result<usize> {
        Ok(0)
    }

    fn send(&mut self, buffer: &[u8]) -> Result<usize> {
        self.netinfo.sent = self.handle.write(buffer).map_err(crate::error::Error::Buffer)?;
        self.handle.flush().map_err(crate::error::Error::Buffer)?;
        Ok(self.netinfo.sent)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.netinfo.received = super::tcp_read(&mut self.handle, buffer)?;
        Ok(self.netinfo.received)
    }

    fn uses_leading_length(&self) -> bool {
        true
    }

    fn mode(&self) -> Protocol {
        Protocol::Tcp
    }

    fn network_info(&self) -> &NetworkInfo {
        self.netinfo()
    }

    // fn local(&self) -> std::io::Result<SocketAddr> {
    //     self.handle.local_addr()
    // }

    // fn peer(&self) -> std::io::Result<SocketAddr> {
    //     self.handle.peer_addr()
    // }
}
