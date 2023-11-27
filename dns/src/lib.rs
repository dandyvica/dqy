pub mod buffer;
pub mod error;
pub mod network;
pub mod rfc;


#[cfg(test)]
use type2network::{FromNetworkOrder, ToNetworkOrder};
//use type2network_derive::{FromNetwork, ToNetwork};

// used for boiler plate unit tests for integers, floats etc
#[cfg(test)]
pub fn to_network_test<T: ToNetworkOrder>(val: &T, size: usize, v: &[u8]) {
    let mut buffer: Vec<u8> = Vec::new();
    assert_eq!(val.serialize_to(&mut buffer).unwrap(), size);
    assert_eq!(buffer, v);
}

#[cfg(test)]
pub fn from_network_test<'a, T>(def: Option<T>, val: &T, buf: &'a Vec<u8>)
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
