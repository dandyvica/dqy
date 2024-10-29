pub mod buffer;
pub mod date_time;
pub mod message;
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
    use std::fs::File;
    use type2network::{FromNetworkOrder, ToNetworkOrder};

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
        let mut v: T = if def.is_none() { T::default() } else { def.unwrap() };
        assert!(v.deserialize_from(&mut buffer).is_ok());
        assert_eq!(&v, val);
    }

    // get packets from pcap file
    pub(crate) fn get_packets(pcap_file: &str, query: usize, response: usize) -> (Vec<u8>, Vec<u8>) {
        use pcap_file::pcap::PcapReader;

        let pcap = File::open(pcap_file).expect("Error opening pcap file");
        let mut pcap_reader = PcapReader::new(pcap).unwrap();

        let mut index = 0usize;

        let mut ret = (Vec::new(), Vec::new());

        // iterate to find the query and response index
        while let Some(pkt) = pcap_reader.next_packet() {
            let pkt = pkt.unwrap();

            if index == query {
                ret.0 = pkt.data.to_vec();
            } else if index == response {
                ret.1 = pkt.data.to_vec();
            }

            index += 1;
        }

        ret
    }

    // helper macro to create a function to test all RRs
    // allow to test several RRs in the answer
    #[macro_export]
    macro_rules! test_rdata {
        // pass function name, pcap file name, RData arm, closure containing unit tests
        // $fname: function name
        // $file: pcap file name
        // $tcp: true if TCP was used
        // $index: packet number in the pcap file
        // $arm: RData enum arm
        // $closure: code to test the function
        ($fname:ident, $file:literal, $tcp:literal, $index:literal, $arm:path, $closure:tt) => {
            #[test]
            fn $fname() -> crate::error::Result<()> {
                {
                    // extract response packet
                    let data = get_packets($file, 0, $index);

                    // manage TCP length if any
                    let mut resp_buffer = if $tcp {
                        // DNS message starts at offset 0x44 when using TCP
                        std::io::Cursor::new(&data.1[0x44..])
                    } else {
                        // DNS message starts at offset 0x2A when using UDP
                        std::io::Cursor::new(&data.1[0x2A..])
                    };

                    println!("{:X?}", resp_buffer);

                    let mut resp = Response::default();
                    resp.deserialize_from(&mut resp_buffer)?;

                    let answer = resp.answer.unwrap();

                    for (i, a) in answer.iter().enumerate() {
                        if let $arm(x) = &a.r_data {
                            $closure(&x, i);
                            //Ok(())
                        } else {
                            panic!("RData not found in file {}", $file)
                        }
                    }

                    Ok(())
                }
            }
        };
    }
}
