use std::fmt;
use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr};

// use log::trace;
use type2network::FromNetworkOrder;

use super::domain::DomainName;

use crate::dns::buffer::Buffer;
use crate::new_rd_length;

// Gateway format is depending on type (https://datatracker.ietf.org/doc/html/rfc4025#section-2.5)
#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
enum Gateway {
    NoGateway(()),
    IpV4(Ipv4Addr),
    IpV6(Ipv6Addr),
    Domain(DomainName),
}

impl Gateway {
    fn len(&self) -> usize {
        match self {
            Gateway::NoGateway(_) => 0,
            Gateway::IpV4(_) => 4,
            Gateway::IpV6(_) => 16,
            Gateway::Domain(dn) => dn.len(),
        }
    }
}

impl Default for Gateway {
    fn default() -> Self {
        Self::NoGateway(())
    }
}

impl fmt::Display for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Gateway::NoGateway(_) => write!(f, "."),
            Gateway::IpV4(ip4) => write!(f, "{}", ip4),
            Gateway::IpV6(ip6) => write!(f, "{}", ip6),
            Gateway::Domain(dn) => write!(f, "{}", dn),
        }
    }
}

// https://datatracker.ietf.org/doc/html/rfc4025
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  precedence   | gateway type  |  algorithm  |     gateway     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------+                 +
// ~                            gateway                            ~
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               /
// /                          public key                           /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
#[derive(Debug, Default)]
pub struct IPSECKEY {
    pub(super) rd_length: u16,

    precedence: u8,
    gateway_type: u8,
    algorithm: u8,
    gateway: Gateway,
    public_key: Buffer,
}

// auto-implement new
new_rd_length!(IPSECKEY);

impl fmt::Display for IPSECKEY {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {}",
            self.precedence,
            self.gateway_type,
            self.algorithm,
            self.gateway,
            self.public_key.to_base64()
        )
    }
}

// Custom serialization
use serde::{ser::SerializeMap, Serialize, Serializer};
impl Serialize for IPSECKEY {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_map(Some(5))?;
        seq.serialize_entry("precedence", &self.precedence)?;
        seq.serialize_entry("gateway_type", &self.gateway_type)?;
        seq.serialize_entry("algorithm", &self.algorithm)?;
        seq.serialize_entry("gateway", &self.gateway.to_string())?;
        seq.serialize_entry("public_key", &self.public_key.to_base64())?;
        seq.end()
    }
}

impl<'a> FromNetworkOrder<'a> for IPSECKEY {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        // deserialize "easy" fields
        self.precedence.deserialize_from(buffer)?;
        self.gateway_type.deserialize_from(buffer)?;
        self.algorithm.deserialize_from(buffer)?;

        // gateway depends on gateway_type
        // The following values are defined:
        // 0  No gateway is present.
        // 1  A 4-byte IPv4 address is present.
        // 2  A 16-byte IPv6 address is present.
        // 3  A wire-encoded domain name is present.
        match self.gateway_type {
            0 => self.gateway = Gateway::NoGateway(()),
            1 => {
                // deserialize ipv4
                let mut ip = Ipv4Addr::UNSPECIFIED;
                ip.deserialize_from(buffer)?;
                self.gateway = Gateway::IpV4(ip)
            }
            2 => {
                // deserialize ipv4
                let mut ip = Ipv6Addr::UNSPECIFIED;
                ip.deserialize_from(buffer)?;
                self.gateway = Gateway::IpV6(ip)
            }
            3 => {
                let mut dn = DomainName::default();
                dn.deserialize_from(buffer)?;
                self.gateway = Gateway::Domain(dn)
            }
            // unspecified
            _ => self.gateway = Gateway::NoGateway(()),
        }

        // to deserialize the key, we need to get the remaining lenght of RData
        let l = self.rd_length - 3 - self.gateway.len() as u16;
        self.public_key = Buffer::with_capacity(l);
        self.public_key.deserialize_from(buffer)?;

        // if a pointer, get pointer value and call
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        dns::rfc::{rdata::RData, response::Response},
        dns::tests::get_packets,
        test_rdata,
    };

    use type2network::FromNetworkOrder;

    use super::IPSECKEY;

    test_rdata!(
        rdata,
        "./tests/pcap/ipseckey.pcap",
        false,
        1,
        RData::IPSECKEY,
        (|x: &IPSECKEY, _| {
            assert_eq!(
                &x.to_string(),
                "10 0 2 . AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ=="
            );
        })
    );
}
