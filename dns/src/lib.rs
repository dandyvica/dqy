pub mod buffer;
pub mod either_or;
pub mod error;
pub mod network;
pub mod rfc;

// Macro used to define getters
#[macro_export]
macro_rules! getter {
    ($struct:ident, $field:ident, $field_type:ty) => {
        impl $struct {
            pub fn $field(&self) -> $field_type {
                self.$field
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Cursor};
    use type2network::{FromNetworkOrder, ToNetworkOrder};

    use pcap_parser::traits::PcapReaderIterator;
    use pcap_parser::*;

    use crate::error::DNSResult;

    pub(crate) fn to_network_test<T: ToNetworkOrder>(val: &T, size: usize, v: &[u8]) {
        let mut buffer: Vec<u8> = Vec::new();
        assert_eq!(val.serialize_to(&mut buffer).unwrap(), size);
        assert_eq!(buffer, v);
    }

    pub(crate) fn from_network_test<'a, T>(def: Option<T>, val: &T, buf: &'a Vec<u8>)
    where
        T: FromNetworkOrder<'a> + Default + std::fmt::Debug + std::cmp::PartialEq,
    {
        let mut buffer = std::io::Cursor::new(buf.as_slice());
        let mut v: T = if def.is_none() {
            T::default()
        } else {
            def.unwrap()
        };
        assert!(v.deserialize_from(&mut buffer).is_ok());
        assert_eq!(&v, val);
    }

    // helper struct to manage tests
    pub(crate) struct PCapData<'a> {
        pub(crate) buf_query: Cursor<&'a [u8]>,
        pub(crate) buf_resp: Cursor<&'a [u8]>,
    }

    // to ease the data for tests, some captures are made using tcpdump and dig
    // and data is saved as a pcap file.
    // by convention, we just capture the query form dig and the response from the resolver.
    pub(crate) fn read_pcap_sample(pcap_file: &str) -> DNSResult<(Vec<u8>, Vec<u8>)> {
        let mut caps = (Vec::new(), Vec::new());

        let file = File::open(pcap_file)?;
        let mut num_blocks = 0u8;
        let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");

        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        // don't need the PCAP header
                        PcapBlockOwned::LegacyHeader(_hdr) => {}

                        // first block is the DNS query, second block is the DNS response
                        PcapBlockOwned::Legacy(b) => {
                            num_blocks += 1;

                            if num_blocks == 1 {
                                caps.0 = b.data[42..].to_vec();
                            } else if num_blocks == 2 {
                                caps.1 = b.data[42..].to_vec();
                            }
                        }
                        PcapBlockOwned::NG(_) => unreachable!(),
                    }
                    reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete) => {
                    reader.refill().unwrap();
                }
                Err(e) => panic!("error while reading: {:?}", e),
            }
        }

        Ok(caps)
    }

    // helper function to write test
    pub(crate) fn get_pcap_buffer(v: &(Vec<u8>, Vec<u8>)) -> PCapData {
        PCapData {
            buf_query: Cursor::new(v.0.as_slice()),
            buf_resp: Cursor::new(v.1.as_slice()),
        }
    }
}
