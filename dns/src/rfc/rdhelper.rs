// some RRs like DS, DNSKEY etc needs the length of RR (rd_length) to be auto-magically deserialized
// this is a helper structure to ease deserialization
use std::{fmt::Debug, marker::PhantomData};

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

#[derive(Debug, Default, FromNetwork)]
pub(super) struct RdHelper<'a, T>
where
    T: Debug + Default + FromNetworkOrder<'a>,
{
    // transmistted through RR deserialization
    #[deser(ignore)]
    rd_length: u16,

    // the RR is DS, DNSKEY etc
    rr: T,

    // because of the pesky 'a lifetime
    #[deser(ignore)]
    phantom: PhantomData<&'a T>,
}

impl<'a, T> RdHelper<'a, T>
where
    T: Debug + Default + FromNetworkOrder<'a>,
{
    pub fn new(len: u16) -> Self {
        let mut x = Self::default();
        x.rd_length = len;

        x
    }
}
