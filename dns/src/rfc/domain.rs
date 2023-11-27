use std::fmt;
use std::io::{Cursor, Result};

use log::trace;
use type2network::{FromNetworkOrder, ToNetworkOrder};

use crate::error::{DNSError, DNSResult, InternalError};

// Domain name: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
#[derive(Debug, Default)]
pub struct DomainName<'a> {
    // a domain name is a list of labels as defined in the RFC1035
    pub labels: Vec<&'a str>,
}

impl<'a> DomainName<'a> {
    // this identifies a compressed label
    fn is_pointer(x: u8) -> bool {
        x >= 192
    }

    // need to know the length is bytes sometimes
    pub fn len(&self) -> usize {
        let mut len = 0usize;

        for l in &self.labels {
            len += l.len() + 1;
        }

        // we add the sentinel
        len + 1
    }

    /// ```
    /// use dns::rfc::domain::DomainName;
    ///
    /// let v = vec![0x03_u8, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x65, 0x00];
    /// let mut dn = DomainName::default();
    /// dn.from_position(0usize, &&v[..]).unwrap();
    /// assert_eq!(dn.labels, &["www", "google", "ie"]);
    /// ```    
    pub fn from_position<'b: 'a>(&mut self, pos: usize, buffer: &&'b [u8]) -> DNSResult<usize> {
        let mut index = pos;

        trace!(
            "from_position(): starting at position: 0x{:X?} ({}) with value: 0x{:X?} ({})",
            index,
            index,
            buffer[index],
            buffer[index]
        );

        loop {
            // we reach the sentinel
            if buffer[index] == 0 {
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
            if DomainName::is_pointer(buffer[index]) {
                // get pointer which is on 2 bytes
                let ptr = [buffer[index], buffer[index + 1]];
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
            let size = buffer[index] as usize;

            // then we convert the label into UTF8
            let label = &buffer[index + 1..index + size + 1];
            //dbg!(label);
            let label_as_utf8 = std::str::from_utf8(label)?;
            // println!(
            //     "label_as_utf8={}, index={}, buffer[index]={:02X?}",
            //     label_as_utf8, index, buffer[index]
            // );

            self.labels.push(label_as_utf8);

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

/// ```
/// use dns::rfc::domain::DomainName;
///
/// let mut dn = DomainName::try_from("www.google.com").unwrap();
/// assert_eq!(dn.to_string(), "www.google.com.");
///
/// let mut dn = DomainName::try_from(".").unwrap();
/// assert_eq!(dn.to_string(), ".");
/// ```
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

/// ```
/// use dns::rfc::domain::DomainName;
///
/// let dn = DomainName::try_from("www.example.com").unwrap();
/// assert_eq!(dn.labels.len(), 3);
/// assert_eq!(dn.labels, &["www", "example", "com"]);
///
/// let dn = DomainName::try_from("com.").unwrap();
/// assert_eq!(dn.labels.len(), 1);
/// assert_eq!(dn.labels, &["com"]);
///
/// let dn = DomainName::try_from(".").unwrap();
/// assert_eq!(dn.labels.len(), 0);
/// assert!(dn.labels.is_empty());

/// assert!(DomainName::try_from("").is_err());
/// ```
impl<'a> TryFrom<&'a str> for DomainName<'a> {
    type Error = DNSError;

    fn try_from(domain: &'a str) -> std::result::Result<Self, Self::Error> {
        if domain.is_empty() {
            return Err(DNSError::DNSInternalError(InternalError::EmptyDomainName));
        }

        // root domain is a special case
        let label_list = if domain == "." {
            Vec::new()
        } else {
            domain
                .split('.')
                .filter(|x| !x.is_empty()) // filter to exclude any potential ending root
                .collect()
        };
        Ok(DomainName { labels: label_list })
    }
}

impl<'a> ToNetworkOrder for DomainName<'a> {
    /// ```
    /// use dns::rfc::domain::DomainName;
    /// use type2network::ToNetworkOrder;
    ///
    /// let dn = DomainName::try_from("www.google.ie").unwrap();
    /// let mut buffer: Vec<u8> = Vec::new();
    ///
    /// assert_eq!(dn.serialize_to(&mut buffer).unwrap(), 15);
    /// assert_eq!(&buffer, &[0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x65, 0x00]);
    /// ```    
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
    /// ```
    /// use std::io::Cursor;
    /// use dns::rfc::domain::DomainName;
    /// use type2network::FromNetworkOrder;
    ///
    /// // with sentinel = 0
    /// let mut buffer = Cursor::new([0x03_u8, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x69, 0x65, 0x00].as_slice());
    /// let mut dn = DomainName::default();
    /// assert!(dn.deserialize_from(&mut buffer).is_ok());
    /// assert_eq!(dn.labels.len(), 3);
    /// assert_eq!(dn.labels, &["www", "google", "ie"]);
    /// ```    
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
