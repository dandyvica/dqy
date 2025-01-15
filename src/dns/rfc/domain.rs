use std::fmt;
use std::io::{Cursor, Result};
use std::ops::Deref;
use std::slice::Iter;

use colored::Colorize;
use log::trace;
use serde::{Serialize, Serializer};
use type2network::{FromNetworkOrder, ToNetworkOrder};
use type2network_derive::ToNetwork;

use crate::error::{self, Dns, Error};
use crate::show::ToColor;

pub const ROOT_DOMAIN: DomainName = DomainName { labels: vec![] };
pub const ROOT: &str = ".";
const PUNY_HEADER: &[u8; 4] = b"xn--";

//---------------------------------------------------------------------------------------------
// Define a Label first
//---------------------------------------------------------------------------------------------

// a label is part of a domain name
#[derive(Debug, Default, Clone, Serialize, ToNetwork)]
struct Label(Vec<u8>);

impl Label {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn size(&self) -> usize {
        self.0.len() + 1
    }

    // true is label representes a punycode
    #[inline]
    fn is_puny(&self) -> bool {
        if self.0.len() < 4 {
            false
        } else {
            &self.0[0..=3] == PUNY_HEADER
        }
    }
}

// Deref to ease methods calls on inner value
impl Deref for Label {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in &self.0 {
            if c > &32 && c < &128 {
                write!(f, "{}", *c as char)?;
            } else {
                write!(f, "\\{:03}", c)?;
            }
        }
        Ok(())
    }
}

// https://datatracker.ietf.org/doc/html/rfc1035#section-3.1
// Name servers and resolvers must
// compare labels in a case-insensitive manner (i.e., A=a), assuming ASCII
// with zero parity.  Non-alphabetic codes must match exactly.
impl PartialEq for Label {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }

        self.iter()
            .zip(other.iter())
            .all(|x| x.0.to_ascii_lowercase() == x.1.to_ascii_lowercase())
    }
}

//---------------------------------------------------------------------------------------------
// Define a domain name as a list of labels
//---------------------------------------------------------------------------------------------

// Domain name: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
#[derive(Default, Clone)]
pub struct DomainName {
    // a domain name is a list of labels as defined in the RFC1035
    labels: Vec<Label>,
}

// a special serializer because the standard serialization isn't what is expected
// for a domain name
impl Serialize for DomainName {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl DomainName {
    // this identifies a compressed label
    // From RFC1035:
    //
    // The pointer takes the form of a two octet sequence:
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // | 1  1|                OFFSET                   |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    fn is_pointer(x: u8) -> bool {
        x >= 0b1100_0000
    }

    // total length is bytes of a domain name as received from network
    // see https://datatracker.ietf.org/doc/html/rfc1035#section-3.1
    // each label contains one byte which is the label size in bytes
    // and ends for \x00
    pub fn size(&self) -> usize {
        self.len() + 1
    }

    // length of domain name as respresented as a string
    pub fn len(&self) -> usize {
        self.iter().map(|l| l.len() + 1).sum()
    }

    // count is different from len in case of UTF-8 chars
    // ex: count("香港.中國.") == 6 len("香港.中國.") == 14
    // this is useful for aligning domain names on ouput
    pub fn count(&self) -> usize {
        if self.is_puny() {
            // convert back first to UTF-8
            let unicode = idna::domain_to_unicode(&self.to_string());
            unicode.0.chars().count()
        } else {
            self.len()
        }
    }

    // true if any of the labels is punycode
    pub fn is_puny(&self) -> bool {
        self.labels.iter().any(|l| l.is_puny())
    }

    // convert domain name to UTF-8
    pub fn to_unicode(&self) -> error::Result<String> {
        let conv = idna::domain_to_unicode(&self.to_string());
        if let Err(e) = conv.1 {
            Err(Error::IDNA(e))
        } else {
            Ok(conv.0)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    // iterator on labels
    fn iter(&self) -> Iter<'_, Label> {
        self.labels.iter()
    }

    pub fn create_from_position(&mut self, pos: usize, buffer: &[u8]) -> error::Result<usize> {
        let mut index = pos;
        let at_index = *buffer.get(index).ok_or(Error::Dns(Dns::CantCreateDomainName))?;

        trace!(
            "from_position(): starting at position: 0x{:X?} ({}) with value: 0x{:X?} ({})",
            index,
            index,
            at_index,
            at_index
        );

        loop {
            // always check if out of bounds
            let at_index = *buffer.get(index).ok_or(Error::Dns(Dns::CantCreateDomainName))?;

            // we reach the sentinel
            if at_index == 0 {
                //dbg!("from_position(): found sentinel", &self.labels);
                break;
            }

            // we reached a pointer
            // From RFC1035:
            //
            // The pointer takes the form of a two octet sequence:
            // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // | 1  1|                OFFSET                   |
            // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //
            //    The first two bits are ones.  This allows a pointer to be distinguished
            //    from a label, since the label must begin with two zero bits because
            //    labels are restricted to 63 octets or less.  (The 10 and 01 combinations
            //    are reserved for future use.)  The OFFSET field specifies an offset from
            //    the start of the message (i.e., the first octet of the ID field in the
            //    domain header).  A zero offset specifies the first byte of the ID field,
            //    etc.
            if DomainName::is_pointer(at_index) {
                let at_index_plus = *buffer.get(index + 1).ok_or(Error::Dns(Dns::CantCreateDomainName))?;

                // get pointer which is on 2 bytes
                let ptr = [at_index, at_index_plus];
                let pointer = u16::from_be_bytes(ptr);

                // println!("pointer={:0b}", pointer);
                // println!("pointer shifted={:0b}", (pointer << 2) >> 2);

                // pointer is the offset releative to the ID field in the domain header
                let pointer = ((pointer << 2) >> 2) as usize;
                //println!("pointer={:0b}", pointer);

                // recursively call the same method with the pointer as starting point
                let _ = self.create_from_position(pointer, buffer);
                return Ok(index + 2);
            }

            // otherwise, regular processing: the first byte is the string length
            let size = at_index as usize;

            // then we convert the label into UTF8
            //let label = &buffer[index + 1..index + size + 1];

            let limb = buffer
                .get(index + 1..index + size + 1)
                .ok_or(Error::Dns(Dns::CantCreateDomainName))?;

            let label = Label(limb.to_vec());

            //dbg!(label);
            //let label_as_utf8 = std::str::from_utf8(label)?;
            //let label_as_utf8: &str = label.into()?;

            if label.len() > 63 {
                return Err(Error::Dns(Dns::DomainLabelTooLong));
            }
            // println!(
            //     "label_as_utf8={}, index={}, buffer[index]={:02X?}",
            //     label_as_utf8, index, buffer[index]
            // );

            self.labels.push(label);

            // adjust index
            index += size + 1;
        }

        // println!(
        //     "end index: {} with value: {:X?}",
        //     index + 1,
        //     buffer[index + 1]
        // );

        Ok(index + 1)
    }
}

impl PartialEq for DomainName {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }

        self.iter().zip(other.iter()).all(|x| x.0 == x.1)
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            write!(f, ".")?;
        } else {
            for l in &self.labels {
                write!(f, "{}.", l)?;
            }
        }

        Ok(())
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl ToColor for DomainName {
    fn to_color(&self) -> colored::ColoredString {
        self.to_string().bright_green()
        // self.to_string().truecolor(NAME_COLOR.0, NAME_COLOR.1, NAME_COLOR.2)
    }
}

// Convert from a ref
impl<'a> TryFrom<&'a DomainName> for DomainName {
    type Error = Error;

    fn try_from(domain: &'a DomainName) -> std::result::Result<Self, Self::Error> {
        Ok(domain.clone())
    }
}

// Convert a str to a domain name
impl<'a> TryFrom<&'a str> for DomainName {
    type Error = Error;

    fn try_from(domain: &'a str) -> std::result::Result<Self, Self::Error> {
        if domain.is_empty() {
            return Err(Error::Dns(Dns::EmptyDomainName));
        }

        // root domain
        if domain == "." {
            return Ok(DomainName::default());
        }

        // domain too long
        if domain.len() > 255 {
            return Err(Error::Dns(Dns::DomainNameTooLong));
        }

        // test IDNA: if so, convert to puny
        let dom = if domain.is_ascii() {
            domain
        } else {
            &idna::domain_to_ascii(domain).map_err(Error::IDNA)?
        };

        // root domain is a special case
        let label_list = dom
            .split('.')
            .filter(|x| !x.is_empty()) // filter to exclude any potential ending root
            .map(|x| Label(x.as_bytes().to_vec()))
            .collect();

        // create the domain name struct
        let dn = DomainName { labels: label_list };

        // test for correctness
        if dn.labels.iter().any(|x| x.len() > 63) {
            return Err(Error::Dns(Dns::DomainLabelTooLong));
        }
        Ok(dn)
    }
}

impl ToNetworkOrder for DomainName {
    fn serialize_to(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        let mut length = 0usize;

        for label in &self.labels {
            // write label: length first, and then chars
            length += (label.len() as u8).serialize_to(buffer)?;
            length += label.serialize_to(buffer)?;
        }

        // trailing 0 means end of domain name
        length += 0_u8.serialize_to(buffer)?;
        Ok(length)
    }
}

impl<'a> FromNetworkOrder<'a> for DomainName {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> Result<()> {
        // dbg!("============================");

        // loop through the vector
        let start_position = buffer.position() as usize;
        // dbg!(start_position);

        // get a reference on inner data
        let inner_ref = buffer.get_ref();

        // fill-in labels from inner data
        let new_position = self.create_from_position(start_position, inner_ref).unwrap();

        // set new position
        buffer.set_position(new_position as u64);
        //println!("domain============>{}, new_pos={}", self, new_position);

        trace!("create domain: <{}>, length={}", self, self.len());

        // if a pointer, get pointer value and call
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size() {
        let dn = DomainName::try_from("www.google.com").unwrap();
        assert_eq!(dn.size(), 16);
    }

    #[test]
    fn len() {
        let dn = DomainName::try_from("www.google.com").unwrap();
        assert_eq!(dn.len(), 15);
    }

    #[test]
    fn count() {
        // xn--j6w193g.xn--fiqz9s. puny is == 香港.中國.
        let dn = DomainName::try_from("xn--j6w193g.xn--fiqz9s.").unwrap();
        assert_eq!(dn.count(), 6);

        let dn = DomainName::try_from("www.google.com").unwrap();
        assert_eq!(dn.count(), 15);
    }

    #[test]
    fn puny() {
        let dn = DomainName::try_from("xn--j6w193g.xn--fiqz9s.").unwrap();
        assert!(dn.is_puny());

        let dn = DomainName::try_from("www.google.com").unwrap();
        assert!(!dn.is_puny());
    }

    #[test]
    fn from_position() {
        let v = vec![
            0x03_u8, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x65, 0x00,
        ];
        let mut dn = DomainName::default();
        dn.create_from_position(0usize, &&v[..]).unwrap();
        assert_eq!(
            dn.labels,
            &[
                Label("www".as_bytes().to_vec()),
                Label("google".as_bytes().to_vec()),
                Label("ie".as_bytes().to_vec())
            ]
        );
    }

    #[test]
    fn equal() {
        let d1 = DomainName::try_from("www.google.com").unwrap();
        let d2 = DomainName::try_from("www.google.fr").unwrap();
        assert!(d1 != d2);
        let d1 = DomainName::try_from("www.google.com").unwrap();
        let d2 = DomainName::try_from("www.google.org").unwrap();
        assert!(d1 != d2);
        let d1 = DomainName::try_from("www.google.com").unwrap();
        let d2 = DomainName::try_from("www.google.com").unwrap();
        assert!(d1 == d2);
        let d1 = DomainName::try_from("www.google.com").unwrap();
        let d2 = DomainName::try_from("WWW.GOOGLE.com").unwrap();
        assert!(d1 == d2);
    }

    #[test]
    fn display() {
        let dn = DomainName::try_from("www.google.com").unwrap();
        assert_eq!(dn.to_string(), "www.google.com.");
        let dn = DomainName::try_from(".").unwrap();
        assert_eq!(dn.to_string(), ".");
    }

    #[test]
    fn try_from() {
        let dn = DomainName::try_from("www.example.com").unwrap();
        assert_eq!(dn.labels.len(), 3);
        assert_eq!(
            dn.labels,
            &[
                Label("www".as_bytes().to_vec()),
                Label("example".as_bytes().to_vec()),
                Label("com".as_bytes().to_vec())
            ]
        );
        let dn = DomainName::try_from("com.").unwrap();
        assert_eq!(dn.labels.len(), 1);
        assert_eq!(dn.labels, &[Label("com".as_bytes().to_vec())]);
        let dn = DomainName::try_from(".").unwrap();
        assert_eq!(dn.labels.len(), 0);
        assert!(dn.labels.is_empty());
        assert!(DomainName::try_from("").is_err());

        let long_label = (0..64).map(|_| "X").collect::<String>();
        let domain = format!("{}.org", long_label);
        assert!(DomainName::try_from(domain.as_str()).is_err());

        let domain = (0..255).map(|_| "X").collect::<String>();
        assert!(DomainName::try_from(domain.as_str()).is_err());

        let _domain = DomainName::try_from("0.0.9.3.2.7.e.f.f.f.3.6.6.7.2.e.4.8.0.3.0.7.4.1.0.0.2.ip6.arpa").unwrap();
    }

    #[test]
    fn serialize_to() {
        use type2network::ToNetworkOrder;
        let dn = DomainName::try_from("www.google.ie").unwrap();
        let mut buffer: Vec<u8> = Vec::new();
        assert_eq!(dn.serialize_to(&mut buffer).unwrap(), 15);
        assert_eq!(
            &buffer,
            &[0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x65, 0x00]
        );
    }

    #[test]
    fn deserialize_from() {
        use std::io::Cursor;
        use type2network::FromNetworkOrder;
        // with sentinel = 0
        let mut buffer = Cursor::new(
            [
                0x03_u8, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x65, 0x00,
            ]
            .as_slice(),
        );
        let mut dn = DomainName::default();
        assert!(dn.deserialize_from(&mut buffer).is_ok());
        assert_eq!(dn.labels.len(), 3);
        assert_eq!(
            dn.labels,
            &[
                Label("www".as_bytes().to_vec()),
                Label("google".as_bytes().to_vec()),
                Label("ie".as_bytes().to_vec())
            ]
        );
    }
}
