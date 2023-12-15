use std::fmt;

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

// Cookie: https://www.rfc-editor.org/rfc/rfc5001.html
#[derive(Debug, Default, ToNetwork)]
pub struct COOKIE {
    client_cookie: Vec<u8>,
    server_cookie: Option<Vec<u8>>,
}
