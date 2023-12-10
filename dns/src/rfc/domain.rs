use std::fmt;
use std::io::{Cursor, Result};
use std::ops::Deref;
use std::slice::Iter;

use log::trace;
use type2network::{FromNetworkOrder, ToNetworkOrder};

use crate::err_internal;
use crate::error::{DNSResult, Error, ProtocolError};

//---------------------------------------------------------------------------------------------
// Define a Label first
//---------------------------------------------------------------------------------------------

// a label is part of a domain name
#[derive(Debug, Default)]
struct Label<'a>(&'a str);

// Deref to ease methods calls on inner value
impl<'a> Deref for Label<'a> {
    type Target = &'a str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> fmt::Display for Label<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// to convert a label into a str
impl<'a> TryFrom<&'a [u8]> for Label<'a> {
    type Error = std::str::Utf8Error;

    fn try_from(slice: &'a [u8]) -> std::result::Result<Self, Self::Error> {
        let s = std::str::from_utf8(slice)?;
        Ok(Label(s))
    }
}

// https://datatracker.ietf.org/doc/html/rfc1035#section-3.1
// Name servers and resolvers must
// compare labels in a case-insensitive manner (i.e., A=a), assuming ASCII
// with zero parity.  Non-alphabetic codes must match exactly.
impl<'a> PartialEq for Label<'a> {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }

        self.chars()
            .zip(other.chars())
            .all(|x| x.0.to_ascii_lowercase() == x.1.to_ascii_lowercase())
    }
}

//---------------------------------------------------------------------------------------------
// Define a domain name as a list of labels
//---------------------------------------------------------------------------------------------

// Domain name: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
#[derive(Debug, Default)]
pub struct DomainName<'a> {
    // a domain name is a list of labels as defined in the RFC1035
    labels: Vec<Label<'a>>,
}

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

    // +1 because of the ending 0
    pub fn len(&self) -> usize {
        self.labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1
    }

    // iterator on labels
    fn iter(&self) -> Iter<'_, Label> {
        self.labels.iter()
    }

    pub fn from_position<'b: 'a>(&mut self, pos: usize, buffer: &&'b [u8]) -> DNSResult<usize> {
        let mut index = pos;
        let at_index = *buffer
            .get(index)
            .ok_or(err_internal!(CantCreateDomainName))?;

        trace!(
            "from_position(): starting at position: 0x{:X?} ({}) with value: 0x{:X?} ({})",
            index,
            index,
            at_index,
            at_index
        );

        loop {
            // always check if out of bounds
            let at_index = *buffer
                .get(index)
                .ok_or(err_internal!(CantCreateDomainName))?;

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
                let at_index_plus = *buffer
                    .get(index + 1)
                    .ok_or(err_internal!(CantCreateDomainName))?;

                // get pointer which is on 2 bytes
                let ptr = [at_index, at_index_plus];
                let pointer = u16::from_be_bytes(ptr);

                // println!("pointer={:0b}", pointer);
                // println!("pointer shifted={:0b}", (pointer << 2) >> 2);

                // pointer is the offset releative to the ID field in the domain header
                let pointer = ((pointer << 2) >> 2) as usize;
                //println!("pointer={:0b}", pointer);

                // recursively call the same method with the pointer as starting point
                let _ = self.from_position(pointer, buffer);
                return Ok(index + 2);
            }

            // otherwise, regular processing: the first byte is the string length
            let size = at_index as usize;

            // then we convert the label into UTF8
            //let label = &buffer[index + 1..index + size + 1];

            let limb = buffer
                .get(index + 1..index + size + 1)
                .ok_or(err_internal!(CantCreateDomainName))?;

            let label = Label::try_from(limb)?;

            //dbg!(label);
            //let label_as_utf8 = std::str::from_utf8(label)?;
            //let label_as_utf8: &str = label.into()?;

            if label.len() > 63 {
                return Err(err_internal!(DomainLabelTooLong));
            }
            // println!(
            //     "label_as_utf8={}, index={}, buffer[index]={:02X?}",
            //     label_as_utf8, index, buffer[index]
            // );

            self.labels.push(Label(&label));

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

impl<'a> PartialEq for DomainName<'a> {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }

        self.iter().zip(other.iter()).all(|x| x.0 == x.1)
    }
}

impl<'a> fmt::Display for DomainName<'a> {
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

impl<'a> TryFrom<&'a str> for DomainName<'a> {
    type Error = Error;

    fn try_from(domain: &'a str) -> std::result::Result<Self, Self::Error> {
        if domain.is_empty() {
            return Err(err_internal!(EmptyDomainName));
        }

        // root domain is a special case
        let label_list = if domain == "." {
            Vec::new()
        } else {
            domain
                .split('.')
                .filter(|x| !x.is_empty()) // filter to exclude any potential ending root
                .map(|x| Label(x))
                .collect()
        };

        // create the domain name struct
        let dn = DomainName { labels: label_list };

        // test for correctness
        if dn.len() > 255 {
            return Err(err_internal!(DomainNameTooLong));
        }
        if dn.labels.iter().any(|x| x.len() > 63) {
            return Err(err_internal!(DomainLabelTooLong));
        }
        Ok(dn)
    }
}

impl<'a> ToNetworkOrder for DomainName<'a> {
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

impl<'a> FromNetworkOrder<'a> for DomainName<'a> {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> Result<()> {
        //dbg!("============================");

        // loop through the vector
        let start_position = buffer.position() as usize;
        //dbg!(start_position);

        // get a reference on inner data
        let inner_ref = buffer.get_ref();

        // fill-in labels from inner data
        let new_position = self.from_position(start_position, inner_ref).unwrap();

        // set new position
        buffer.set_position(new_position as u64);
        //println!("domain============>{}, new_pos={}", self, new_position);

        // if a pointer, get pointer value and call
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len() {
        let dn = DomainName::try_from("www.google.com").unwrap();
        assert_eq!(dn.len(), 16);
    }

    #[test]
    fn from_position() {
        let v = vec![
            0x03_u8, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x65,
            0x00,
        ];
        let mut dn = DomainName::default();
        dn.from_position(0usize, &&v[..]).unwrap();
        assert_eq!(dn.labels, &[Label("www"), Label("google"), Label("ie")]);
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
        assert_eq!(dn.labels, &[Label("www"), Label("example"), Label("com")]);
        let dn = DomainName::try_from("com.").unwrap();
        assert_eq!(dn.labels.len(), 1);
        assert_eq!(dn.labels, &[Label("com")]);
        let dn = DomainName::try_from(".").unwrap();
        assert_eq!(dn.labels.len(), 0);
        assert!(dn.labels.is_empty());
        assert!(DomainName::try_from("").is_err());

        let long_label = (0..64).map(|_| "X").collect::<String>();
        let domain = format!("{}.org", long_label);
        assert!(DomainName::try_from(domain.as_str()).is_err());

        let domain = (0..255).map(|_| "X").collect::<String>();
        assert!(DomainName::try_from(domain.as_str()).is_err());
    }

    #[test]
    fn serialize_to() {
        use type2network::ToNetworkOrder;
        let dn = DomainName::try_from("www.google.ie").unwrap();
        let mut buffer: Vec<u8> = Vec::new();
        assert_eq!(dn.serialize_to(&mut buffer).unwrap(), 15);
        assert_eq!(
            &buffer,
            &[
                0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x65,
                0x00
            ]
        );
    }

    #[test]
    fn deserialize_from() {
        use std::io::Cursor;
        use type2network::FromNetworkOrder;
        // with sentinel = 0
        let mut buffer = Cursor::new(
            [
                0x03_u8, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69,
                0x65, 0x00,
            ]
            .as_slice(),
        );
        let mut dn = DomainName::default();
        assert!(dn.deserialize_from(&mut buffer).is_ok());
        assert_eq!(dn.labels.len(), 3);
        assert_eq!(dn.labels, &[Label("www"), Label("google"), Label("ie")]);
    }
}
