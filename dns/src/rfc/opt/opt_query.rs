// An OPT RR as sent along with the query in the additional section.
// Here, OPT RR = OptQuery, which is made of a vector of OptOption, where the variable data is an enum of OptData
// OptOption is:
//
// +0 (MSB)                            +1 (LSB)
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 0: |                          OPTION-CODE                          |
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 2: |                         OPTION-LENGTH                         |
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 4: |                                                               |
//    /                          OPTION-DATA                          /
//    /                                                               /
//    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//
// doc: https://www.rfc-editor.org/rfc/rfc6891#section-6

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use crate::rfc::{qclass::Class, qtype::QType, resource_record::ResourceRecord};

use super::{opt_code::OptOptionCode, opt_data::OptOptionData, opt_option::OptOption};

#[derive(Debug, Default)]
pub struct OptQuery<'a>(pub ResourceRecord<'a, Vec<OptOption>>);

impl<'a> OptQuery<'a> {
    pub fn new(bufsize: Option<u16>) -> Self {
        let mut opt = OptQuery::default();
        opt.0.r#type = QType::OPT;
        opt.0.class = Class::Payload(bufsize.unwrap_or(1232));

        opt
    }

    pub fn set_edns_nsid(&mut self) {
        let mut opt_option = OptOption::default();
        opt_option.code = OptOptionCode::NSID as u16;

        self.0.r_data.push(opt_option);
    }
}


// Option data are specific
