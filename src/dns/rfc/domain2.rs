use std::borrow::Cow;
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

//pub const ROOT_DOMAIN: DomainName = DomainName { labels: vec![] };
pub const ROOT: &str = ".";
const PUNY_HEADER: &[u8; 4] = b"xn--";

//───────────────────────────────────────────────────────────────────────────────────
// Define a Label first
//───────────────────────────────────────────────────────────────────────────────────
const MAX_LABEL_LENGTH: usize = 63;

// a label is part of a domain name
#[derive(Debug, Default, ToNetwork, Serialize)]
pub struct Label<'a>(Cow<'a, [u8]>);

impl Label<'_> {
    // true if label represents a punycode
    #[inline]
    fn is_puny(&self) -> bool {
        if self.0.len() < 4 {
            false
        } else {
            &self.0[0..=3] == PUNY_HEADER
        }
    }
}

// clone to have an owned value
impl<'a> Clone for Label<'a> {
    fn clone(&self) -> Label<'a> {
        Label(self.0.to_owned())
    }
}

// Deref to ease methods calls on inner value
impl<'a> Deref for Label<'a> {
    type Target = Cow<'a, [u8]>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// label is taken from a buffer: take reference
impl<'a> TryFrom<&'a [u8]> for Label<'a> {
    type Error = Error;

    fn try_from(buffer: &'a [u8]) -> std::result::Result<Self, Self::Error> {
        if buffer.len() > MAX_LABEL_LENGTH {
            Err(Error::Dns(Dns::DomainLabelTooLong))
        } else {
            Ok(Label(Cow::from(buffer)))
        }
    }
}

// label is taken from a string ref: take ownership
impl TryFrom<&str> for Label<'_> {
    type Error = Error;

    fn try_from(buffer: &str) -> std::result::Result<Self, Self::Error> {
        if buffer.len() > MAX_LABEL_LENGTH {
            Err(Error::Dns(Dns::DomainLabelTooLong))
        } else {
            Ok(Label(Cow::from(buffer.as_bytes().to_vec())))
        }
    }
}

impl fmt::Display for Label<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.iter() {
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
impl PartialEq for Label<'_> {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }

        self.iter()
            .zip(other.iter())
            .all(|x| x.0.to_ascii_lowercase() == x.1.to_ascii_lowercase())
    }
}

//───────────────────────────────────────────────────────────────────────────────────
// Define a domain name as a list of labels
//───────────────────────────────────────────────────────────────────────────────────
const MAX_DOMAIN_LENGTH: usize = 255; // including dots but not last one

// Domain name: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
// a domain name is a list of labels as defined in the RFC1035
#[derive(Debug, Default, Clone, ToNetwork)]
pub struct DomainName<'a>(Vec<Label<'a>>);

impl<'a> DomainName<'a> {
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

    pub fn create_from_position<'b: 'a>(&mut self, pos: usize, buffer: &&'b [u8]) -> crate::error::Result<usize> {
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

            let label = Label::try_from(limb)?;

            //dbg!(label);
            //let label_as_utf8 = std::str::from_utf8(label)?;
            //let label_as_utf8: &str = label.into()?;

            // println!(
            //     "label_as_utf8={}, index={}, buffer[index]={:02X?}",
            //     label_as_utf8, index, buffer[index]
            // );

            self.0.push(label);

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

    // total length is bytes of a domain name as received from network
    // see https://datatracker.ietf.org/doc/html/rfc1035#section-3.1
    // each label contains one byte which is the label size in bytes
    // and ends for \x00
    pub fn size(&self) -> usize {
        self.len() + 1
    }

    // length of domain name = label octets and label length octets
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
        self.iter().any(|l| l.is_puny())
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
}

// Deref to ease methods calls on inner value
impl<'a> Deref for DomainName<'a> {
    type Target = Vec<Label<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// a domain name ends with the root: .
impl fmt::Display for DomainName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            write!(f, ".")?;
        } else {
            for l in self.iter() {
                write!(f, "{}.", l)?;
            }
        }

        Ok(())
    }
}

impl PartialEq for DomainName<'_> {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }

        self.iter().zip(other.iter()).all(|x| x.0 == x.1)
    }
}

// Convert a str to a domain name
impl TryFrom<&str> for DomainName<'_> {
    type Error = Error;

    fn try_from(domain: &str) -> std::result::Result<Self, Self::Error> {
        // no domain
        if domain.is_empty() {
            return Err(Error::Dns(Dns::EmptyDomainName));
        }

        // root domain
        if domain == "." {
            return Ok(DomainName::default());
        }

        // split by '.'
        let (labels, errors): (Vec<_>, Vec<_>) = domain
            .split('.')
            .filter(|x| !x.is_empty()) // filter to exclude any potential ending root
            .map(|x| Label::try_from(x))
            .partition(|x| x.is_ok());

        // only possible error is that one of the labels is too long
        if !errors.is_empty() {
            return Err(Error::Dns(Dns::DomainLabelTooLong));
        }

        // create the domain name
        let dn = DomainName(labels.into_iter().map(|x| x.unwrap()).collect());

        // test for correctness
        if dn.len() > MAX_DOMAIN_LENGTH {
            return Err(Error::Dns(Dns::DomainNameTooLong));
        }

        Ok(dn)
    }
}

// impl<'a> ToNetworkOrder for DomainName<'a> {
//     fn serialize_to(&self, buffer: &mut Vec<u8>) -> Result<usize> {
//         let mut length = 0usize;

//         for label in self.iter() {
//             // write label: length first, and then chars
//             length += (label.len() as u8).serialize_to(buffer)?;
//             length += label.serialize_to(buffer)?;
//         }

//         // trailing 0 means end of domain name
//         length += 0_u8.serialize_to(buffer)?;
//         Ok(length)
//     }
// }

impl<'a> FromNetworkOrder<'a> for DomainName<'a> {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> Result<()> {
        //dbg!("============================");

        // loop through the vector
        let start_position = buffer.position() as usize;
        //dbg!(start_position);

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
    fn label() {
        // try_from
        let buf = [1u8; 64];
        assert!(Label::try_from(buf.as_slice()).is_err());

        // is_puny
        assert!(Label::try_from("xn--kxae4bafwg").unwrap().is_puny());
        assert!(!Label::try_from("kxae4bafwg").unwrap().is_puny());
        assert!(!Label::try_from("xxx").unwrap().is_puny());

        // display
        let x = [0x77u8, 0x77, 0x77];
        let l = Label::try_from(&x[..]).unwrap();
        assert_eq!(l.to_string(), "www");

        // equality
        let l1 = Label::try_from("www").unwrap();
        let l2 = Label::try_from("Www").unwrap();
        assert_eq!(l1, l2);
    }

    #[test]
    fn domain() {
        // try_from
        let large_dn = "x".repeat(128).repeat(2);
        assert!(DomainName::try_from(large_dn.as_str()).is_err());

        // len, size
        let dn = DomainName::try_from("www.google.com").unwrap();
        assert_eq!(dn.len(), 15);
        assert_eq!(dn.size(), 16);
        assert_eq!(dn.to_string(), "www.google.com.");
        assert_eq!(DomainName::default().to_string(), ".");

        // is_puny
        let dn = DomainName::default();
        assert!(!dn.is_puny());

        let dn = DomainName::try_from("xn--kxae4bafwg.xn--pxaix.gr.").unwrap();
        assert!(dn.is_puny());

        let dn = DomainName::try_from("www.google.com").unwrap();
        assert!(!dn.is_puny());

        // to_unicode
        let dn = DomainName::try_from("xn--kxae4bafwg.xn--pxaix.gr.").unwrap();
        assert_eq!(dn.to_unicode().unwrap(), "ουτοπία.δπθ.gr.");

        // eq
        let dn1 = DomainName::try_from("www.google.com").unwrap();
        let dn2 = DomainName::try_from("www.google.COM").unwrap();
        assert_eq!(dn1, dn2);
    }
}
