//! RRSet is a list of resource records for the same domain name.
//!

use std::ops::Deref;

use show::Show;
use type2network::FromNetworkOrder;
use type2network_derive::FromNetwork;

#[allow(unused_imports)]
use rand::seq::IteratorRandom;
use serde::Serialize;

use super::resource_record::ResourceRecord;

#[derive(Debug, Default, FromNetwork, Serialize)]
pub(super) struct RRSet(Vec<ResourceRecord>);

impl RRSet {
    // necessery for deserialization
    pub fn with_capacity(capa: usize) -> Self {
        Self(Vec::with_capacity(capa))
    }

    // return a list of RRs having the same QType
    // pub fn filter(&self, qt: &QType) -> Vec<&RR> {
    //     self.0.iter().filter(|x| x.r#type == *qt).collect()
    // }

    // // return a random RR corresponding to the QType
    // pub fn random(&self, qt: &QType) -> Option<&RR> {
    //     let mut rng = rand::thread_rng();

    //     self.filter(qt).into_iter().choose(&mut rng)
    // }
}

impl Deref for RRSet {
    type Target = Vec<ResourceRecord>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Show for RRSet {
    fn show(&self, display_options: &show::DisplayOptions) {
        for rr in &self.0 {
            rr.show(display_options);
        }
    }
}
