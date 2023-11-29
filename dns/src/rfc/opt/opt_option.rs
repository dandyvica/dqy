use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use super::opt_data::OptOptionData;

#[derive(Debug, Default, ToNetwork)]
pub struct OptOption {
    pub code: u16,
    pub length: u16,
    pub data: Vec<OptOptionData>,
}