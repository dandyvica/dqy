use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
};

use resolver::ResolverList;

use crate::protocol::IPVersion;

#[derive(Debug, Default)]
pub struct EndPoint {
    pub server: String,
    pub addrs: Vec<SocketAddr>,
}

impl EndPoint {
    // only keep IPV4 or IPV6 or both addresses
    pub fn retain(&mut self, ver: &IPVersion) {
        match ver {
            IPVersion::Any => (),
            IPVersion::V4 => self.addrs.retain(|ip| ip.is_ipv4()),
            IPVersion::V6 => self.addrs.retain(|ip| ip.is_ipv6()),
        }
    }
}

// build end point from the resolvers taken from a file
impl TryFrom<(&PathBuf, u16)> for EndPoint {
    type Error = error::Error;

    fn try_from(value: (&PathBuf, u16)) -> Result<Self, Self::Error> {
        let resolvers = ResolverList::try_from(value.0.as_path())?;
        let ip_list = resolvers
            .to_ip_list()
            .iter()
            .map(|ip| SocketAddr::from((*ip, value.1)))
            .collect();

        Ok(Self {
            server: String::new(),
            addrs: ip_list,
        })
    }
}

impl TryFrom<(&str, u16)> for EndPoint {
    type Error = error::Error;

    fn try_from(value: (&str, u16)) -> Result<Self, Self::Error> {
        // if no server, use host resolvers
        if value.0.is_empty() {
            let resolvers = ResolverList::new()?;
            let ip_list = resolvers
                .to_ip_list()
                .iter()
                .map(|ip| SocketAddr::from((*ip, value.1)))
                .collect();

            Ok(Self {
                server: String::new(),
                addrs: ip_list,
            })
        } else {
            let addrs = value.to_socket_addrs()?;

            Ok(Self {
                server: value.0.to_string(),
                addrs: addrs.collect(),
            })
        }
    }
}
