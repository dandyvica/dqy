use std::{
    fmt,
    io::{Cursor, Read},
    //slice::Iter,
};

use log::trace;
use type2network::FromNetworkOrder;

use error::{err_internal, Error, ProtocolError};

use super::qtype::QType;

// https://datatracker.ietf.org/doc/html/rfc5155#section-3.2.1
// https://datatracker.ietf.org/doc/html/rfc4034#section-4.1.2

// The RR type space is split into 256 window blocks, each representing
// the low-order 8 bits of the 16-bit RR type space.  Each block that
// has at least one active RR type is encoded using a single octet
// window number (from 0 to 255), a single octet bitmap length (from 1
// to 32) indicating the number of octets used for the window block's
// bitmap, and up to 32 octets (256 bits) of bitmap.
#[derive(Debug, Default)]
pub(super) struct TypeBitMaps {
    // this field is used to pass the total length of the bitmaps from incoming RR
    pub(super) types_length: u16,

    // types as a result of the NSEC3 query
    pub(super) types: Vec<QType>,
}

impl TypeBitMaps {
    pub fn new<T: Into<u16> + std::fmt::Debug>(len: T) -> Self {
        dbg!(&len);
        Self {
            types_length: len.into(),
            types: Vec::new(),
        }
    }
}

// impl TypeBitMaps {
//     pub fn iter(&self) -> Iter<'_, QType> {
//         self.types.iter()
//     }
// }

impl<'a> FromNetworkOrder<'a> for TypeBitMaps {
    fn deserialize_from(&mut self, buffer: &mut Cursor<&'a [u8]>) -> std::io::Result<()> {
        // read exactly the number of bytes of the whole type bit maps
        trace!("TypeBitMaps length {}", self.types_length);
        let mut buf = vec![0u8; self.types_length as usize];
        buffer.read_exact(&mut buf)?;

        let list = WindowList::try_from(buf.as_slice())
            .map_err(|_| std::io::Error::other("can deserialize NSEC3 RR"))?;

        self.types = Vec::<QType>::try_from(list)
            .map_err(|_| std::io::Error::other("can deserialize NSEC3 RR"))?;

        Ok(())
    }
}

impl fmt::Display for TypeBitMaps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: Vec<String> = self.types.iter().map(|q| q.to_string()).collect();
        write!(f, "{}", s.join(" "))
    }
}

// Custom serialization
use serde::{Serialize, Serializer};
impl Serialize for TypeBitMaps {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// a window in NSEC3/NSEC RR is a list of types
// https://datatracker.ietf.org/doc/html/rfc5155#section-3.2
// block0 encodes QTypes from A (bit 1 of bitmap) to URI (bit 256)
// block1 encodes QTypes from CAA (257, bit 1 of bitmap) to ? (bit 256)
//
// formula: QType value = (bit number of bitmap in the window) + (window block ID)*256
#[derive(Debug, Default)]
struct Window<'a> {
    // Window Block #
    id: u8,

    // Bitmap Length
    length: u8,

    // Bitmap
    data: &'a [u8],
}

// we could have more than one window, 256 at most
#[derive(Debug, Default)]
struct WindowList<'a>(Vec<Window<'a>>);

impl<'a> TryFrom<&'a [u8]> for WindowList<'a> {
    type Error = error::Error;

    #[allow(clippy::field_reassign_with_default)]
    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        let mut v = Vec::new();
        let mut i = 0usize;

        while i < buf.len() {
            let mut win = Window::default();

            // extract window number
            win.id = *buf.get(i).ok_or(err_internal!(CantCreateNSEC3Types))?;
            i += 1;

            // length should be between 1 and 32
            win.length = *buf.get(i).ok_or(err_internal!(CantCreateNSEC3Types))?;
            i += 1;
            debug_assert!((1..=32).contains(&win.length));

            // now just point to types bits data
            win.data = buf
                .get(i..i + win.length as usize)
                .ok_or(err_internal!(CantCreateNSEC3Types))?;
            i += win.length as usize;

            v.push(win);
        }

        debug_assert!(v.len() <= 256);

        Ok(WindowList(v))
    }
}

impl<'a> TryFrom<WindowList<'a>> for Vec<QType> {
    type Error = error::Error;

    fn try_from(list: WindowList) -> Result<Self, Self::Error> {
        let mut v = Vec::new();

        // window #0 => Qtype from 1 to 256
        // window #1 => Qtype from 257 to 512
        // etc
        for win in list.0 {
            // each byte in the data can hold up to 7 Qtypes (bit0 is not meaningful)
            // we test each bit != 0 which is the Qtype value
            // e.g.: data is: &[0x62, 0x01, 0x80, 0x08, 0x00, 0x02, 0x90];
            // 0x62 01100010: bit 1 is set
            // 0x62 01100010: bit 2 is set
            // 0x62 01100010: bit 6 is set
            // 0x01 00000001: bit 15 is set
            // 0x80 10000000: bit 16 is set
            // 0x8 00001000: bit 28 is set
            // 0x2 00000010: bit 46 is set
            // 0x90 10010000: bit 48 is set
            // 0x90 10010000: bit 51 is set
            // data Qtypes => A NS SOA MX TXT AAAA RRSIG DNSKEY NSEC3PARAM
            for u in win.data.iter().enumerate() {
                for i in (0..=7).rev() {
                    if (u.1 >> i) & 1u8 == 1 {
                        // this bit is set
                        let bit = ((7 - i) + u.0 * 8) + 256 * win.id as usize;

                        // then we can create the QType
                        // can safely unwrap because of the fallback value
                        let qt = QType::try_from(bit as u16).unwrap();
                        // println!(
                        //     "{:x} {}: bit {} is set",
                        //     u.1,
                        //     format!("{:08b}", u.1),
                        //     (7 - i) + u.0 * 8
                        // );

                        v.push(qt);
                    }
                }
            }
        }

        Ok(v)
    }
    // split
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list() {
        // single window
        let buf = vec![0u8, 4, 1, 2, 3, 4];
        let list = WindowList::try_from(buf.as_slice()).unwrap();
        assert_eq!(list.0.len(), 1);
        assert_eq!(list.0[0].id, 0);
        assert_eq!(list.0[0].length, 4);
        assert_eq!(&list.0[0].data, &[1, 2, 3, 4]);

        let buf = vec![0u8, 4, 1, 2, 3, 4, 0, 2, 1, 2, 0, 3, 1, 2, 3];
        let list = WindowList::try_from(buf.as_slice()).unwrap();
        assert_eq!(list.0.len(), 3);
        assert_eq!(list.0[0].id, 0);
        assert_eq!(list.0[0].length, 4);
        assert_eq!(&list.0[0].data, &[1, 2, 3, 4]);
        assert_eq!(list.0[1].id, 0);
        assert_eq!(list.0[1].length, 2);
        assert_eq!(&list.0[1].data, &[1, 2]);
        assert_eq!(list.0[2].id, 0);
        assert_eq!(list.0[2].length, 3);
        assert_eq!(&list.0[2].data, &[1, 2, 3]);

        let mut buf = vec![0u8, 32];
        let x: Vec<_> = (1..=32).into_iter().collect();
        buf.extend(&x);

        let list = WindowList::try_from(buf.as_slice()).unwrap();
        assert_eq!(list.0.len(), 1);
        assert_eq!(list.0[0].id, 0);
        assert_eq!(list.0[0].length, 32);
        assert_eq!(list.0[0].data, x.as_slice());
    }

    #[test]
    fn qtypes_creation() {
        // single window0
        let buf = vec![0u8, 7, 0x62, 0x01, 0x80, 0x08, 0x00, 0x02, 0x90];
        let list = WindowList::try_from(buf.as_slice()).unwrap();
        let type_list = Vec::<QType>::try_from(list).unwrap();
        assert_eq!(
            type_list,
            vec![
                QType::A,
                QType::NS,
                QType::SOA,
                QType::MX,
                QType::TXT,
                QType::AAAA,
                QType::RRSIG,
                QType::DNSKEY,
                QType::NSEC3PARAM
            ]
        );

        // double windows 0 & 1
        let buf = vec![
            0x00, 0x09, 0x40, 0x05, 0x80, 0x0c, 0x54, 0x0b, 0x0d, 0x04, 0xc0, 0x01, 0x01, 0xc0,
        ];
        let list = WindowList::try_from(buf.as_slice()).unwrap();
        let type_list = Vec::<QType>::try_from(list).unwrap();
        assert_eq!(
            type_list,
            vec![
                QType::A,
                QType::HINFO,
                QType::MX,
                QType::TXT,
                QType::AAAA,
                QType::LOC,
                QType::SRV,
                QType::NAPTR,
                QType::CERT,
                QType::SSHFP,
                QType::RRSIG,
                QType::NSEC,
                QType::TLSA,
                QType::SMIMEA,
                QType::HIP,
                QType::OPENPGPKEY,
                QType::SVCB,
                QType::HTTPS,
                QType::URI,
                QType::CAA
            ]
        );
        // assert_eq!(
        //     &list.types.to_string(),
        //     "A,HINFO,MX,TXT,AAAA,LOC,SRV,NAPTR,CERT,SSHFP,RRSIG,NSEC,TLSA,SMIMEA,HIP,OPENPGPKEY,SVCB,HTTPS,URI,CAA"
        // );
    }
}
