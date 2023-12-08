// In some cases, when a value is not matching an enum (like QClass), we need to still manage the value
// (e.g.: TYPE65559). So use Either enum for those cases.

use std::{fmt, ops::Deref};

use either::*;

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

#[derive(Debug, ToNetwork)]
pub struct EitherOr<L, R>(Either<L, R>)
where
    L: ToNetworkOrder,
    R: ToNetworkOrder;

impl<L, R> EitherOr<L, R>
where
    L: ToNetworkOrder,
    R: ToNetworkOrder,
{
    pub fn new_left(left: L) -> Self {
        Self(Left(left))
    }
    pub fn new_right(right: R) -> Self {
        Self(Right(right))
    }
}

impl<L, R> Deref for EitherOr<L, R>
where
    L: ToNetworkOrder,
    R: ToNetworkOrder,
{
    type Target = Either<L, R>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// By default, left side
impl<L, R> Default for EitherOr<L, R>
where
    L: Default + ToNetworkOrder,
    R: ToNetworkOrder,
{
    fn default() -> Self {
        EitherOr(Either::<L, R>::Left(L::default()))
    }
}

impl<L, R> fmt::Display for EitherOr<L, R>
where
    L: fmt::Display + ToNetworkOrder,
    R: fmt::Display + ToNetworkOrder,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// impl<L, R> ToNetworkOrder for EitherOr<L, R>
// where
//     L: ToNetworkOrder,
//     R: ToNetworkOrder,
// {
//     fn serialize_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<usize> {
//         let length = match &self.0 {
//             Either::Left(l) => l.serialize_to(buffer)?,
//             Either::Right(r) => r.serialize_to(buffer)?,
//         };

//         Ok(length)
//     }
// }

// In this case, we can't determine by ourselves which variant it's gonna be.
// We restrict that implementation to those for which an unit-like variant value could
// be something else. By convention, the Left variant will contains the enum (like QClass).
// impl<'a, L, R> FromNetworkOrder<'a> for EitherOr<L, R>
// where
//     L: TryFrom<u16, Error = u16>,
//     R: From<u16>,
// {
//     fn deserialize_from(&mut self, buffer: &mut std::io::Cursor<&'a [u8]>) -> std::io::Result<()> {
//         // try to deserialize left first
//         let value = buffer.read_u16::<BigEndian>()?;

//         match L::try_from(value) {
//             Ok(q) => *self = Self(Either::<L, R>::Left(q)),
//             Err(_) => *self = Self(Either::<L, R>::Right(R::from(value))),
//         }

//         Ok(())
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc::qtype::QType;

    use crate::tests::to_network_test;

    #[test]
    fn either_or() {
        // to_network
        let q = QType::AAAA;
        let either_or = EitherOr(Either::<QType, u16>::Left(q));

        to_network_test(&either_or, 2, &[0x00, 28]);
        //from_network_test(None, &q, &vec![0x00, 28]);
    }
}
