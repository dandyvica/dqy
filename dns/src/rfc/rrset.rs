//! RRSet is a list of resource records for the same domain name.
//!

use std::ops::Deref;

use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

use rand::seq::IteratorRandom;
use serde::Serialize;

use super::{qtype::QType, resource_record::RR};

#[derive(Debug, Default, FromNetwork, Serialize)]
pub(super) struct RRSet<'a>(Vec<RR<'a>>);

impl<'a> RRSet<'a> {
    // necessery for deserialization
    pub fn with_capacity(capa: usize) -> Self {
        Self(Vec::with_capacity(capa))
    }

    // return a list of RRs having the same QType
    pub fn filter(&self, qt: &QType) -> Vec<&RR<'a>> {
        self.0.iter().filter(|x| x.r#type == *qt).collect()
    }

    // return a random RR corresponding to the QType
    pub fn random(&self, qt: &QType) -> Option<&RR<'a>> {
        let mut rng = rand::thread_rng();

        self.filter(qt).into_iter().choose(&mut rng)
    }
}

impl<'a> Deref for RRSet<'a> {
    type Target = Vec<RR<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
