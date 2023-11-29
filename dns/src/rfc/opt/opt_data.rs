//use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

#[derive(Debug, ToNetwork)]
pub enum OptOptionData {
    NSID(NSID),
    COOKIE(COOKIE),
}

impl Default for OptOptionData {
    fn default() -> Self {
        OptOptionData::NSID(())
    }
}

//---------------------------------------------------------------------------
// all option data are specified here

// NSID: https://www.rfc-editor.org/rfc/rfc5001.html
pub type NSID = ();

// Cookie: https://www.rfc-editor.org/rfc/rfc5001.html
#[derive(Debug, Default, ToNetwork)]
pub struct COOKIE {
    client_cookie: u8,
    server_cookie: Vec<u8>,
}
